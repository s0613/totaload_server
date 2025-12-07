package com.isoplatform.api.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.*;

@Component
public class Gemini {

    private final WebClient webClient;
    private final String apiKey;
    private final String model;
    private final ObjectMapper objectMapper;
    private final HttpClient httpClient;

    public Gemini(@Value("${gemini.api-key}") String apiKey,
                  @Value("${gemini.base-url}") String baseUrl,
                  @Value("${gemini.model:gemini-2.0-flash}") String model,
                  WebClient.Builder webClientBuilder) {
        this.apiKey = Objects.requireNonNull(apiKey, "gemini.api-key is null");
        this.model = Objects.requireNonNull(model, "gemini.model is null");
        this.objectMapper = new ObjectMapper();
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        this.webClient = webClientBuilder
                .baseUrl(baseUrl)
                .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(50 * 1024 * 1024))
                .build();
    }

    public List<Boolean> checkImageDescriptions(List<String> imageUrls, List<String> descriptions) {
        if (imageUrls == null || descriptions == null) {
            throw new IllegalArgumentException("이미지 URL 리스트와 설명 리스트가 null입니다.");
        }
        if (imageUrls.size() != descriptions.size()) {
            throw new IllegalArgumentException("이미지 URL 리스트와 설명 리스트의 크기가 다릅니다.");
        }
        if (imageUrls.isEmpty()) {
            return Collections.emptyList();
        }

        try {
            // URL에서 이미지 다운로드
            List<byte[]> imageBytesList = downloadImages(imageUrls);

            Map<String, Object> requestBody = createRequestBody(imageBytesList, descriptions);

            String response = webClient.post()
                    .uri("/v1beta/models/" + model + ":generateContent?key=" + apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(60))
                    .block();

            return parseResponse(response, descriptions.size());

        } catch (WebClientResponseException e) {
            String body = e.getResponseBodyAsString();
            throw new RuntimeException("Gemini API 호출 실패: HTTP " + e.getStatusCode().value() + " - " + safeBody(body), e);
        } catch (Exception e) {
            throw new RuntimeException("Gemini API 호출 중 오류: " + e.getMessage(), e);
        }
    }

    private List<byte[]> downloadImages(List<String> imageUrls) {
        List<byte[]> imageBytesList = new ArrayList<>();

        for (int i = 0; i < imageUrls.size(); i++) {
            String url = imageUrls.get(i);
            if (url == null || url.trim().isEmpty()) {
                throw new IllegalArgumentException("이미지 URL이 비어있습니다: " + (i + 1) + "번째");
            }

            try {
                byte[] imageBytes;

                // data URI scheme 처리
                if (url.startsWith("data:")) {
                    imageBytes = decodeDataUri(url);
                } else {
                    // HTTP URL 처리
                    HttpRequest request = HttpRequest.newBuilder()
                            .uri(URI.create(url.trim()))
                            .timeout(Duration.ofSeconds(10))
                            .build();

                    HttpResponse<byte[]> response = httpClient.send(request,
                            HttpResponse.BodyHandlers.ofByteArray());

                    if (response.statusCode() != 200) {
                        throw new RuntimeException("이미지 다운로드 실패: HTTP " + response.statusCode() +
                                " for URL: " + url);
                    }

                    imageBytes = response.body();
                }

                if (imageBytes == null || imageBytes.length == 0) {
                    throw new RuntimeException("빈 이미지 데이터: " + url);
                }

                imageBytesList.add(imageBytes);

            } catch (IOException | InterruptedException e) {
                throw new RuntimeException("이미지 다운로드 중 오류 발생: " + url + " - " + e.getMessage(), e);
            }
        }

        return imageBytesList;
    }

    private byte[] decodeDataUri(String dataUri) {
        try {
            // data:image/jpeg;base64,/9j/4AAQ... 형식에서 base64 부분만 추출
            if (!dataUri.contains(",")) {
                throw new IllegalArgumentException("잘못된 data URI 형식: " + dataUri);
            }

            String[] parts = dataUri.split(",", 2);
            if (parts.length != 2) {
                throw new IllegalArgumentException("잘못된 data URI 형식: " + dataUri);
            }

            String base64Data = parts[1];
            return Base64.getDecoder().decode(base64Data);
        } catch (IllegalArgumentException e) {
            throw new RuntimeException("data URI 디코딩 실패: " + e.getMessage(), e);
        }
    }

    private Map<String, Object> createRequestBody(List<byte[]> images, List<String> descs) {
        // 기존 코드와 동일
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

        Map<String, Object> finalInstruction = new HashMap<>();
        finalInstruction.put("text",
                "위에 제시된 순서대로 각 이미지-설명 쌍의 결과를 판단하세요. " +
                        "오직 JSON 배열 형식으로만 반환하세요. 예: [true,false,true]");
        parts.add(finalInstruction);

        userMsg.put("role", "user");
        userMsg.put("parts", parts);
        contents.add(userMsg);

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

    private List<Boolean> parseResponse(String response, int expectedSize) {
        // 기존 코드와 동일
        if (response == null || response.isBlank()) {
            throw new IllegalStateException("빈 응답을 수신했습니다.");
        }
        try {
            JsonNode root = objectMapper.readTree(response);

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

            JsonNode textNode = parts.get(0).path("text");
            if (textNode.isMissingNode() || textNode.asText().isBlank()) {
                throw new IllegalStateException("응답 텍스트를 찾을 수 없습니다.");
            }

            String jsonArrayText = textNode.asText().trim();

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

            if (out.size() != expectedSize) {
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

    private String detectMime(byte[] bytes) {
        if (bytes == null || bytes.length < 12) return "application/octet-stream";

        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xFF && (bytes[1] & 0xFF) == 0xD8 && (bytes[2] & 0xFF) == 0xFF) {
            return "image/jpeg";
        }

        if (bytes.length >= 8) {
            byte[] sig = Arrays.copyOf(bytes, 8);
            String hex = Hex.encodeHexString(sig).toLowerCase(Locale.ROOT);
            if (hex.equals("89504e470d0a1a0a")) {
                return "image/png";
            }
        }

        if (bytes.length >= 12) {
            String riff = new String(Arrays.copyOfRange(bytes, 0, 4));
            String webp = new String(Arrays.copyOfRange(bytes, 8, 12));
            if ("RIFF".equals(riff) && "WEBP".equals(webp)) {
                return "image/webp";
            }
        }

        return "image/jpeg";
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

    /**
     * 인증서 이미지 분석 - 구조화된 JSON 반환
     * PDF에서 변환된 이미지들을 분석하여 차량 정보를 추출합니다.
     *
     * @param imageUrls 분석할 이미지 URL 리스트
     * @return 분석 결과 JsonNode (차량 정보 포함)
     */
    public JsonNode analyzeCertificate(List<String> imageUrls) {
        if (imageUrls == null || imageUrls.isEmpty()) {
            throw new IllegalArgumentException("이미지 URL 리스트가 비어있습니다.");
        }

        try {
            // 1. 이미지 다운로드
            List<byte[]> imageBytesList = downloadImages(imageUrls);

            // 2. 요청 바디 생성 (분석용)
            Map<String, Object> requestBody = createAnalysisRequestBody(imageBytesList);

            // 3. Gemini API 호출
            String response = webClient.post()
                    .uri("/v1beta/models/" + model + ":generateContent?key=" + apiKey)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(requestBody)
                    .retrieve()
                    .bodyToMono(String.class)
                    .timeout(Duration.ofSeconds(120))  // 분석은 더 오래 걸릴 수 있음
                    .block();

            // 4. 응답 파싱
            return parseAnalysisResponse(response);

        } catch (WebClientResponseException e) {
            String body = e.getResponseBodyAsString();
            throw new RuntimeException("Gemini API 호출 실패: HTTP " + e.getStatusCode().value() + " - " + safeBody(body), e);
        } catch (Exception e) {
            throw new RuntimeException("인증서 분석 중 오류: " + e.getMessage(), e);
        }
    }

    /**
     * 인증서 분석용 요청 바디 생성
     */
    private Map<String, Object> createAnalysisRequestBody(List<byte[]> images) {
        Map<String, Object> body = new HashMap<>();
        List<Map<String, Object>> contents = new ArrayList<>();

        Map<String, Object> userMsg = new HashMap<>();
        List<Map<String, Object>> parts = new ArrayList<>();

        // 이미지들을 parts에 추가
        for (byte[] img : images) {
            Map<String, Object> imagePart = new HashMap<>();
            Map<String, Object> inlineData = new HashMap<>();
            inlineData.put("mime_type", detectMime(img));
            inlineData.put("data", Base64.getEncoder().encodeToString(img));
            imagePart.put("inline_data", inlineData);
            parts.add(imagePart);
        }

        // 분석 지시사항
        Map<String, Object> instructionPart = new HashMap<>();
        instructionPart.put("text",
                "위 이미지는 차량 인증서입니다. 다음 정보를 추출하여 JSON으로 반환하세요:\n" +
                        "{\n" +
                        "  \"manufacturer\": \"제조사\",\n" +
                        "  \"modelName\": \"모델명\",\n" +
                        "  \"vin\": \"차대번호 (17자리)\",\n" +
                        "  \"manuYear\": \"제조연도 (숫자)\",\n" +
                        "  \"displacement\": \"배기량 (cc 단위 문자열)\",\n" +
                        "  \"fuelType\": \"연료 타입\",\n" +
                        "  \"seatCount\": \"좌석 수 (숫자)\",\n" +
                        "  \"variant\": \"트림/파생형\",\n" +
                        "  \"inspectCountry\": \"검사 국가\",\n" +
                        "  \"inspectDate\": \"검사일자 (YYYY-MM-DD)\",\n" +
                        "  \"mileage\": \"주행거리 (숫자, km)\",\n" +
                        "  \"colorCode\": \"외장색상\",\n" +
                        "  \"engineNumber\": \"엔진번호\",\n" +
                        "  \"confidence\": \"분석 신뢰도 (0.0-100.0)\"\n" +
                        "}\n" +
                        "정보가 없으면 null로 표기하세요. JSON만 반환하고 다른 설명은 포함하지 마세요.");
        parts.add(instructionPart);

        userMsg.put("role", "user");
        userMsg.put("parts", parts);
        contents.add(userMsg);

        // JSON 응답 모드 설정
        Map<String, Object> genCfg = new HashMap<>();
        genCfg.put("response_mime_type", "application/json");

        body.put("contents", contents);
        body.put("generationConfig", genCfg);

        return body;
    }

    /**
     * 분석 응답 파싱
     */
    private JsonNode parseAnalysisResponse(String response) {
        if (response == null || response.isBlank()) {
            throw new IllegalStateException("빈 응답을 수신했습니다.");
        }

        try {
            JsonNode root = objectMapper.readTree(response);

            // 안전성 정책 체크
            JsonNode promptFeedback = root.path("promptFeedback");
            if (!promptFeedback.isMissingNode()) {
                JsonNode blockReason = promptFeedback.path("blockReason");
                if (!blockReason.isMissingNode() && !blockReason.asText().isBlank()) {
                    throw new IllegalStateException("요청이 안전성 정책에 의해 차단되었습니다: " + blockReason.asText());
                }
            }

            // candidates 추출
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

            JsonNode textNode = parts.get(0).path("text");
            if (textNode.isMissingNode() || textNode.asText().isBlank()) {
                throw new IllegalStateException("응답 텍스트를 찾을 수 없습니다.");
            }

            String jsonText = textNode.asText().trim();

            // JSON 파싱
            return objectMapper.readTree(jsonText);

        } catch (JsonProcessingException e) {
            throw new RuntimeException("응답 JSON 파싱 실패: " + e.getOriginalMessage() + " / raw=" + abbreviate(response, 800), e);
        }
    }
}