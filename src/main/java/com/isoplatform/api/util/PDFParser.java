package com.isoplatform.api.util;

import com.isoplatform.api.certification.Certificate;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.text.PDFTextStripper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;

@Slf4j
@Component
public class PDFParser {

    private static final String TEMPLATE_PDF = "static/ISO_acrobat.pdf";
    private static final String FONT_PATH    = "static/fonts/Pretendard-Medium.ttf";
    private static final String OUTPUT_DIR   = "certificates/";

    /**
     * PDF 파일에서 전체 텍스트 내용을 추출합니다.
     *
     * @param inputStream PDF 파일 InputStream
     * @return 추출된 PDF 전체 텍스트
     */
    public String parseFullText(InputStream inputStream) {
        try (PDDocument document = PDDocument.load(inputStream)) {
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document);

            log.debug("PDF 텍스트 추출(앞 500자): {}", text.substring(0, Math.min(500, text.length())));

            return text;
        } catch (IOException e) {
            log.error("PDF 텍스트 추출 중 오류 발생", e);
            throw new RuntimeException("PDF 텍스트 추출 중 오류가 발생했습니다.", e);
        }
    }

    /**
     * 인증서 정보를 바탕으로 PDF 파일을 생성합니다.
     *
     * @param certificate 인증서 정보
     * @return 생성된 PDF 파일 경로
     */
    public String createCertificatePdf(Certificate certificate) throws Exception {
        Path dir = Paths.get(OUTPUT_DIR);
        if (!Files.exists(dir)) {
            Files.createDirectories(dir);
        }
        String outFile = OUTPUT_DIR + certificate.getCertNumber() + ".pdf";

        try (InputStream tmpl = new ClassPathResource(TEMPLATE_PDF).getInputStream();
             PDDocument doc   = PDDocument.load(tmpl)) {

            PDAcroForm form = Objects.requireNonNull(doc.getDocumentCatalog().getAcroForm());

            // ── (추가) 폼 필드 이름 모두 찍기 ──
            log.info(">> PDF 폼 필드 목록 시작");
            for (PDField f : form.getFields()) {
                log.info("   • field ▶ {}", f.getFullyQualifiedName());
            }
            log.info(">> PDF 폼 필드 목록 끝");

            // 2-1. Pretendard 글꼴 임베드 & 기본 글꼴 지정
            embedKoreanFont(doc, form);

            // 2-2. 필드 값 채우기
            fillFields(form, certificate);

            // 2-3. appearance 재생성 후 평면화
            form.refreshAppearances();
            form.flatten();

            doc.save(outFile);
            log.info("PDF 저장 완료: {}", outFile);
        }

        return outFile;
    }

    private void embedKoreanFont(PDDocument doc, PDAcroForm form) throws Exception {
        PDResources dr = form.getDefaultResources();
        if (dr == null) {
            dr = new PDResources();
            form.setDefaultResources(dr);
        }

        try (InputStream fontStream = new ClassPathResource(FONT_PATH).getInputStream()) {
            PDType0Font font = PDType0Font.load(doc, fontStream, false);
            String fontName = dr.add(font).getName();
            form.setDefaultAppearance("/" + fontName + " 12 Tf 0 g");

            for (PDField field : form.getFields()) {
                setFieldFont(field, font, fontName);
            }
        }
    }

    private void setFieldFont(PDField field, PDType0Font font, String fontName) {
        try {
            if (field instanceof org.apache.pdfbox.pdmodel.interactive.form.PDTextField textField) {
                String da = "/" + fontName + " 12 Tf 0 g";
                textField.setDefaultAppearance(da);

                for (PDAnnotationWidget widget : textField.getWidgets()) {
                    try {
                        if (widget.getNormalAppearanceStream() != null) {
                            PDResources widgetResources = widget.getNormalAppearanceStream().getResources();
                            if (widgetResources == null) {
                                widgetResources = new PDResources();
                                widget.getNormalAppearanceStream().setResources(widgetResources);
                            }
                            widgetResources.add(font);
                        }
                    } catch (Exception e) {
                        log.debug("위젯 리소스 설정 실패 (무시됨): {}", e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            log.warn("필드 폰트 설정 실패: {}", field.getFullyQualifiedName(), e);
        }
    }

    private void fillFields(PDAcroForm form, Certificate c) {
        Map<String, String> map = Map.ofEntries(
                Map.entry("certNumber",                  c.getCertNumber()),
                Map.entry("issueDate_es_:date",          formatDate(c.getIssueDate())),
                Map.entry("expireDate_es_:date",         formatDate(c.getExpireDate())),
                Map.entry("inspectDate_es_:date",        formatDate(c.getInspectDate())),
                Map.entry("manu_es_:fullname",           c.getManufacturer()),
                Map.entry("modelName",                   c.getModelName()),
                Map.entry("vin",                         c.getVin()),
                Map.entry("manufactureYear_es_:date",    formatNumber(c.getManufactureYear())),
                Map.entry("firstRegisterDate_es_:date",  formatDate(c.getFirstRegisterDate())),
                Map.entry("mileage",                     formatNumber(c.getMileage()) + (c.getMileage() != null ? " km" : "")),
                Map.entry("inspectorCode",               c.getInspectorCode()),
                Map.entry("inspectorName_es_:fullname",  c.getInspectorName()),
                Map.entry("corpName_es_:fullname",       c.getIssuedBy())
        );

        map.forEach((name, value) -> {
            PDField f = form.getField(name);
            if (f == null) {
                log.warn("필드 없음: {}", name);
                return;
            }
            try {
                String safeValue = value == null ? "" : value;
                if (containsKorean(safeValue)) {
                    setKoreanFieldValue(f, safeValue);
                } else {
                    f.setValue(safeValue);
                }
            } catch (Exception e) {
                log.error("setValue {} error: {}", name, e.getMessage());
                try {
                    f.setValue("");
                } catch (IOException ex) {
                    log.error("빈 값 설정도 실패: {}", name, ex);
                }
            }
        });
    }

    private boolean containsKorean(String text) {
        if (text == null || text.isEmpty()) return false;
        return text.chars().anyMatch(c ->
                (c >= 0xAC00 && c <= 0xD7AF) ||
                        (c >= 0x1100 && c <= 0x11FF) ||
                        (c >= 0x3130 && c <= 0x318F)
        );
    }

    private void setKoreanFieldValue(PDField field, String value) throws IOException {
        if (field instanceof org.apache.pdfbox.pdmodel.interactive.form.PDTextField textField) {
            textField.setValue(value);
        } else {
            field.setValue(value);
        }
    }

    private String formatDate(LocalDate d) {
        return d == null ? "" : d.format(DateTimeFormatter.ofPattern("yyyy년 MM월 dd일"));
    }

    private String formatNumber(Number n) {
        return n == null ? "" : n.toString();
    }
}
