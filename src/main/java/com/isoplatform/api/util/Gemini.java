package com.isoplatform.api.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.nio.ByteBuffer;
import java.util.*;

/**
 * Gemini 이미지-설명 매칭 유틸
 * - 각 이미지와 설명의 일치 여부를 boolean로 반환
 * - 모델은 기본값 "gemini-2.0-flash" (exp 지양)
 */
@Component
public class Gemini {

    private final RestTemplate restTemplate;
    private final String apiKey;
    private final String baseUrl;
    private final String model;
    private final ObjectMapper objectMapper;

    public Gemini(@Value("${gemini.api-key}") String apiKey,
                  @Value("${gemini.base-url}") String baseUrl,
                  @Value("${gemini.model:gemini-2.0-flash}") String model) {
        this.apiKey = Objects.requireNonNull(apiKey, "gemini.api-key is null");
        this.baseUrl = Objects.requireNonNull(baseUrl, "gemini.base-url is null");
        this.model = Objects.requireNonNull(model, "gemini.model is null");
        this.objectMapper = new ObjectMapper();

        // 타임아웃 설정
        HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory();
        factory.setConnectTimeout(5_000);
        factory.setReadTimeout(20_000);
        this.restTemplate = new RestTemplate(factory);
    }

    /**
     * 이미지와 설명의 일치 여부를 판정한다.
     * @param imageBytesList 이미지 바이트 배열 리스트 (각 항목이 한 이미지)
     * @param descriptions 각 이미지에 대한 설명 (동일 인덱스)
     * @return 각 항목의 true/false 결과 리스트
     */
    public List<Boolean> checkImageDescriptions(List<byte[]> imageBytesList, List<String> descriptions) {
        if (imageBytesList == null || descriptions == null) {
            throw new IllegalArgumentException("이미지 리스트와 설명 리스트가 null입니다.");
        }
        if (imageBytesList.size() != descriptions.size()) {
            throw new IllegalArgumentException("이미지 리스트와 설명 리스트의 크기가 다릅니다.");
        }
        if (imageBytesList.isEmpty()) {
            return Collections.emptyList();
        }

        try {
            Map<String, Object> requestBody = createRequestBody(imageBytesList, descriptions);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(requestBody, headers);

            String url = baseUrl + "/v1beta/models/" + model + ":generateContent?key=" + apiKey;

            ResponseEntity<String> response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class);

            // HTTP 상태 코드 체크
            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new RuntimeException("Gemini API HTTP 오류: " + response.getStatusCodeValue());
            }
            return parseResponse(response.getBody(), descriptions.size());

        } catch (HttpStatusCodeException e) {
            String body = e.getResponseBodyAsString();
            throw new RuntimeException("Gemini API 호출 실패: HTTP " + e.getStatusCode().value() + " - " + safeBody(body), e);
        } catch (Exception e) {
            throw new RuntimeException("Gemini API 호출 중 오류: " + e.getMessage(), e);
        }
    }

    /**
     * 요청 본문 구성
     * - 이미지와 해당 설명을 번갈아(parts에 interleave) 추가
     * - JSON 배열(boolean[]) 출력 강제
     */
    private Map<String, Object> createRequestBody(List<byte[]> images, List<String> descs) {
        Map<String, Object> body = new HashMap<>();
        List<Map<String, Object>> contents = new ArrayList<>();

        Map<String, Object> userMsg = new HashMap<>();
        List<Map<String, Object>> parts = new ArrayList<>();

        for (int i = 0; i < images.size(); i++) {
            byte[] img = images.get(i);
            String desc = descs.get(i) == null ? "" : descs.get(i).trim();

            Map<String, Object> imagePart = new HashMap<>();
            Map<String, Object> inlineData = new HashMap<>();
            inlineData.put("mime_type", detectMime(img));
            inlineData.put("data", Base64.getEncoder().encodeToString(img));
            imagePart.put("inline_data", inlineData);
            parts.add(imagePart);

            Map<String, Object> textPart = new HashMap<>();
            textPart.put("text", "해당 이미지에 대한 설명: \"" + desc + "\"\n" +
                    "이 이미지와 설명이 일치하면 true, 불일치하면 false로 판단하세요.");
            parts.add(textPart);
        }

        // 최종 출력 요구: 오직 JSON 배열로만 반환
        Map<String, Object> finalInstruction = new HashMap<>();
        finalInstruction.put("text",
                "위에 제시된 순서대로 각 이미지-설명 쌍의 결과를 판단하세요. " +
                        "오직 JSON 배열 형식으로만 반환하세요. 예: [true,false,true]");
        parts.add(finalInstruction);

        userMsg.put("role", "user");
        userMsg.put("parts", parts);
        contents.add(userMsg);

        // generationConfig: JSON 배열(Boolean) 스키마 강제
        Map<String, Object> genCfg = new HashMap<>();
        genCfg.put("response_mime_type", "application/json");

        Map<String, Object> schema = new HashMap<>();
        schema.put("type", "ARRAY");
        Map<String, Object> items = new HashMap<>();
        items.put("type", "BOOLEAN");
        schema.put("items", items);
        genCfg.put("response_schema", schema);

        body.put("contents", contents);
        body.put("generationConfig", genCfg);

        return body;
    }

    /**
     * 응답 파싱
     * - candidates[0].content.parts[0].text 가 JSON 배열 문자열이어야 함
     * - safety block / prompt feedback 등 예외 케이스 처리
     */
    private List<Boolean> parseResponse(String response, int expectedSize) {
        if (response == null || response.isBlank()) {
            throw new IllegalStateException("빈 응답을 수신했습니다.");
        }
        try {
            JsonNode root = objectMapper.readTree(response);

            // safety block 혹은 promptFeedback 확인
            JsonNode promptFeedback = root.path("promptFeedback");
            if (!promptFeedback.isMissingNode()) {
                JsonNode blockReason = promptFeedback.path("blockReason");
                if (!blockReason.isMissingNode() && !blockReason.asText().isBlank()) {
                    throw new IllegalStateException("요청이 안전성 정책에 의해 차단되었습니다: " + blockReason.asText());
                }
            }

            JsonNode candidates = root.path("candidates");
            if (!candidates.isArray() || candidates.isEmpty()) {
                throw new IllegalStateException("응답에 candidates가 없습니다.");
            }

            JsonNode first = candidates.get(0);
            JsonNode content = first.path("content");
            JsonNode parts = content.path("parts");
            if (!parts.isArray() || parts.isEmpty()) {
                throw new IllegalStateException("응답에 parts가 없습니다.");
            }

            // JSON 배열 문자열을 기대
            JsonNode textNode = parts.get(0).path("text");
            if (textNode.isMissingNode() || textNode.asText().isBlank()) {
                throw new IllegalStateException("응답 텍스트를 찾을 수 없습니다.");
            }

            // 모델이 실제 JSON 문자열을 반환하도록 강제했으므로 여기서 parse
            String jsonArrayText = textNode.asText().trim();

            // 혹시 따옴표로 한번 더 싸였으면 제거 시도
            if (jsonArrayText.startsWith("\"") && jsonArrayText.endsWith("\"")) {
                jsonArrayText = jsonArrayText.substring(1, jsonArrayText.length() - 1);
            }

            JsonNode arr = objectMapper.readTree(jsonArrayText);
            if (!arr.isArray()) {
                throw new IllegalStateException("JSON 배열이 아님: " + jsonArrayText);
            }

            List<Boolean> out = new ArrayList<>();
            for (JsonNode n : arr) {
                out.add(n.asBoolean());
            }

            // 결과 개수 검증(옵션)
            if (out.size() != expectedSize) {
                // 크기가 다르면 모델이 빠뜨렸을 가능성 → 보수적으로 패딩
                if (out.size() < expectedSize) {
                    while (out.size() < expectedSize) out.add(Boolean.FALSE);
                } else {
                    out = out.subList(0, expectedSize);
                }
            }
            return out;
        } catch (JsonProcessingException e) {
            throw new RuntimeException("응답 JSON 파싱 실패: " + e.getOriginalMessage() + " / raw=" + abbreviate(response, 800), e);
        }
    }

    /**
     * 간단 MIME 식별 (JPEG/PNG/WEBP)
     */
    private String detectMime(byte[] bytes) {
        if (bytes == null || bytes.length < 12) return "application/octet-stream";

        // JPEG: FF D8 FF
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8 && (bytes[2] & 0xFF) == 0xFF) {
            return "image/jpeg";
        }

        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if (bytes.length >= 8) {
            byte[] sig = Arrays.copyOf(bytes, 8);
            String hex = Hex.encodeHexString(sig).toLowerCase(Locale.ROOT);
            if (hex.equals("89504e470d0a1a0a")) {
                return "image/png";
            }
        }

        // WEBP: "RIFF" .... "WEBP"
        if (bytes.length >= 12) {
            String riff = new String(Arrays.copyOfRange(bytes, 0, 4));
            String webp = new String(Arrays.copyOfRange(bytes, 8, 12));
            if ("RIFF".equals(riff) && "WEBP".equals(webp)) {
                return "image/webp";
            }
        }

        return "image/jpeg"; // 기본값
    }

    private static String safeBody(String s) {
        if (s == null) return "";
        return abbreviate(s.replaceAll("\\s+", " "), 800);
    }

    private static String abbreviate(String s, int max) {
        if (s == null) return "";
        if (s.length() <= max) return s;
        return s.substring(0, max) + "...(truncated)";
    }

    // 디버깅 보조: 바이트를 앞부분만 hex로
    @SuppressWarnings("unused")
    private static String headHex(byte[] bytes, int len) {
        int n = Math.min(len, bytes.length);
        ByteBuffer buf = ByteBuffer.wrap(Arrays.copyOf(bytes, n));
        byte[] head = new byte[n];
        buf.get(head);
        return Hex.encodeHexString(head);
    }
}
