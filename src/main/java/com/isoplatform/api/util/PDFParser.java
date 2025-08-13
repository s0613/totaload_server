package com.isoplatform.api.util;

import com.isoplatform.api.certification.Certificate;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDCIDFontType0;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDNonTerminalField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTextField;
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
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Slf4j
@Component
public class PDFParser {

    private static final String TEMPLATE_PDF = "static/ISO_acrobat.pdf";

    private static final String FONT_PRIMARY = "static/fonts/Pretendard-Medium.ttf";
    private static final String FONT_FALLBACK_TTF = "static/fonts/NotoSansKR-Regular.ttf";

    private static final String OUTPUT_DIR   = "certificates/";
    private static final DateTimeFormatter DF_KR = DateTimeFormatter.ofPattern("yyyy년 MM월 dd일");

    private static final COSName ALIAS_F1 = COSName.getPDFName("F1"); // 메인 폰트 별칭

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

    public String createCertificatePdf(Certificate certificate) throws Exception {
        Path dir = Paths.get(OUTPUT_DIR);
        if (!Files.exists(dir)) Files.createDirectories(dir);
        String outFile = OUTPUT_DIR + certificate.getCertNumber() + ".pdf";

        ClassPathResource cpr = new ClassPathResource(TEMPLATE_PDF);
        try (InputStream tmpl = cpr.getInputStream();
             PDDocument doc   = PDDocument.load(tmpl)) {

            PDAcroForm form = ensureAcroFormReady(doc);

            log.info(">> PDF 폼 필드 목록 시작");
            for (PDField f : getAllFields(form)) {
                log.info("   • field ▶ {}", f.getFullyQualifiedName());
            }
            log.info(">> PDF 폼 필드 목록 끝");

            // F1 등록
            PDFont f1 = embedMainFont(doc, form);

            // AcroForm DR 내 모든 폰트 별칭을 F1로 강제 매핑(문제 폰트 별칭 사전 차단)
            overrideAllDRFontsToF1(form, f1);

            // 기본 DA 통일
            String defaultDA = "/F1 12 Tf 0 g";
            form.setDefaultAppearance(defaultDA);

            // 모든 텍스트 필드에 DA 적용 + 기존 Appearance 제거
            applyDAAndClearAppearanceOnAllTextFields(form, defaultDA);

            // 값 채우기
            fillFieldsLoosely(form, certificate);

            // 새로 Appearance 생성
            try {
                form.refreshAppearances();
            } catch (UnsupportedOperationException uoe) {
                // 혹시 모를 잔여 케이스 완충
                log.warn("refreshAppearances 중 UnsupportedOperationException 발생: {}", uoe.toString());
                // 마지막 방어: NeedAppearances 힌트에 맡기고 flatten 시도
            }

            // 플래튼
            form.flatten();

            doc.save(outFile);
            log.info("PDF 저장 완료: {}", outFile);
        }

        return outFile;
    }

    private PDAcroForm ensureAcroFormReady(PDDocument doc) {
        PDDocumentCatalog catalog = doc.getDocumentCatalog();
        PDAcroForm form = catalog.getAcroForm();
        if (form == null) {
            throw new IllegalStateException("이 PDF에는 AcroForm이 없습니다. 템플릿을 확인하세요.");
        }

        // 뷰어가 Appearance 생성하도록 힌트(우리는 refreshAppearances도 호출)
        form.setNeedAppearances(true);

        if (form.getDefaultResources() == null) {
            PDResources dr = new PDResources();
            dr.put(COSName.getPDFName("Helv"), PDType1Font.HELVETICA);
            form.setDefaultResources(dr);
        }
        if (form.getDefaultAppearance() == null || form.getDefaultAppearance().isEmpty()) {
            form.setDefaultAppearance("/Helv 12 Tf 0 g");
        }
        return form;
    }

    private PDFont embedMainFont(PDDocument doc, PDAcroForm form) {
        PDType0Font f1 = null;

        // 1차: Pretendard
        try (InputStream is = new ClassPathResource(FONT_PRIMARY).getInputStream()) {
            f1 = PDType0Font.load(doc, is, true);
            log.info("폰트 임베드 시도: {}", FONT_PRIMARY);
        } catch (Throwable t) {
            log.warn("기본 폰트 로드 실패: {} -> {}", FONT_PRIMARY, t.toString());
        }

        boolean useFallback = false;
        if (f1 == null) {
            useFallback = true;
        } else {
            try {
                if (f1.getDescendantFont() instanceof PDCIDFontType0) {
                    // Pretendard가 CFF CID로 잡히는 변종 대비
                    useFallback = true;
                    log.warn("Pretendard가 CIDFontType0(CFF)로 로딩됨. 안전한 TTF로 교체합니다.");
                } else {
                    log.info("Pretendard가 CIDFontType2(또는 안전한 타입)로 로딩됨.");
                }
            } catch (Throwable t) {
                useFallback = true;
                log.warn("폰트 타입 점검 중 오류. 폴백 사용: {}", t.toString());
            }
        }

        if (useFallback) {
            try (InputStream is2 = new ClassPathResource(FONT_FALLBACK_TTF).getInputStream()) {
                f1 = PDType0Font.load(doc, is2, true);
                log.info("폴백 폰트 임베드 성공: {}", FONT_FALLBACK_TTF);
            } catch (Throwable t2) {
                log.error("폴백 폰트 로드 실패: {} -> {}", FONT_FALLBACK_TTF, t2.toString());
                throw new RuntimeException(
                        "필수 폰트를 로드할 수 없습니다. " +
                                "TTF 한글 폰트를 클래스패스에 추가하세요: " + FONT_FALLBACK_TTF, t2);
            }
        }

        // 폭 계산 사전 테스트
        try {
            f1.getStringWidth("한글 테스트:년월일_ABC123");
        } catch (Throwable t) {
            log.warn("폰트 폭 계산 테스트 경고: {}", t.toString());
        }

        // F1 등록
        PDResources dr = form.getDefaultResources();
        dr.put(ALIAS_F1, f1);

        // 관성적으로 남아 있을 수 있는 Helv 별칭도 F1로 덮어쓰기(DA가 /Helv일 때 강제 차단)
        dr.put(COSName.getPDFName("Helv"), f1);

        log.info("폰트 임베드 완료: {}", (useFallback ? FONT_FALLBACK_TTF : FONT_PRIMARY));
        return f1;
    }

    /**
     * DR에 이미 등록되어 있는 모든 폰트 별칭을 F1로 강제 덮어씁니다.
     * (문제가 되는 CFF CID Type0 폰트 별칭을 사전에 제거/대체)
     */
    private void overrideAllDRFontsToF1(PDAcroForm form, PDFont f1) {
        PDResources dr = form.getDefaultResources();
        List<COSName> names = new ArrayList<>();
        for (COSName n : dr.getFontNames()) {
            names.add(n);
        }
        for (COSName n : names) {
            try {
                PDFont existing = dr.getFont(n);
                if (existing != null) {
                    // 어떤 별칭이건 간에 F1로 통일
                    dr.put(n, f1);
                }
            } catch (Exception ignore) {
            }
        }
        // 최종적으로 /F1도 확실히 세팅
        dr.put(ALIAS_F1, f1);
    }

    /**
     * 모든 텍스트 필드에 DA를 적용하고, 기존 위젯 Appearance를 제거하여
     * refreshAppearances가 F1만 사용해 새로 그리도록 강제합니다.
     */
    private void applyDAAndClearAppearanceOnAllTextFields(PDAcroForm form, String da) {
        for (PDField field : getAllFields(form)) {
            if (field instanceof PDTextField) {
                PDTextField tf = (PDTextField) field;
                tf.setDefaultAppearance(da);

                // 위젯에 남아있는 Appearance를 제거(초기화)
                for (PDAnnotationWidget widget : tf.getWidgets()) {
                    try {
                        PDAppearanceDictionary ap = widget.getAppearance();
                        if (ap != null) {
                            widget.setAppearance(null); // 기존 외형 제거
                        }
                    } catch (Exception e) {
                        log.debug("위젯 Appearance 제거 실패(무시): {} ({})", field.getFullyQualifiedName(), e.getMessage());
                    }
                }
            }
        }
    }

    private List<PDField> getAllFields(PDAcroForm form) {
        List<PDField> out = new ArrayList<>();
        for (PDField f : form.getFields()) collectFieldsRecursively(f, out);
        return out;
    }

    private void collectFieldsRecursively(PDField field, List<PDField> out) {
        out.add(field);
        if (field instanceof PDNonTerminalField) {
            PDNonTerminalField nt = (PDNonTerminalField) field;
            for (PDField kid : nt.getChildren()) collectFieldsRecursively(kid, out);
        }
    }

    private List<PDField> resolveFieldsByBaseName(PDAcroForm form, String baseName) {
        List<PDField> all = getAllFields(form);

        List<PDField> exact = all.stream()
                .filter(f -> baseName.equals(f.getFullyQualifiedName()))
                .collect(Collectors.toList());
        if (!exact.isEmpty()) return exact;

        Pattern idxPat = Pattern.compile("^" + Pattern.quote(baseName) + "#\\d+$");
        List<PDField> indexed = all.stream()
                .filter(f -> {
                    String n = f.getFullyQualifiedName();
                    return n != null && idxPat.matcher(n).matches();
                })
                .sorted(Comparator.comparing(PDField::getFullyQualifiedName))
                .collect(Collectors.toList());
        if (!indexed.isEmpty()) return indexed;

        List<PDField> prefixed = all.stream()
                .filter(f -> {
                    String n = f.getFullyQualifiedName();
                    return n != null && (n.startsWith(baseName + "#") || n.startsWith(baseName + "."));
                })
                .sorted(Comparator.comparing(PDField::getFullyQualifiedName))
                .collect(Collectors.toList());

        return prefixed;
    }

    private void setTextToAll(PDAcroForm form, String baseName, String value) {
        List<PDField> targets = resolveFieldsByBaseName(form, baseName);
        if (targets.isEmpty()) {
            log.warn("필드 없음: {}", baseName);
            return;
        }
        String safe = value == null ? "" : value;

        for (PDField f : targets) {
            try {
                if (f instanceof PDTextField) {
                    ((PDTextField) f).setValue(safe);
                } else {
                    f.setValue(safe);
                }
                log.debug("필드 세팅 완료: {} ← '{}'", f.getFullyQualifiedName(), safe);
            } catch (UnsupportedOperationException uoe1) {
                // 최후 방어: ASCII 완화
                String ascii = safe.replaceAll("[^\\x20-\\x7E]", " ");
                try {
                    if (f instanceof PDTextField) {
                        ((PDTextField) f).setValue(ascii);
                        log.warn("인코딩 실패로 ASCII 치환 적용: {} ← '{}'", f.getFullyQualifiedName(), ascii);
                    } else {
                        f.setValue(ascii);
                    }
                } catch (Exception e3) {
                    log.error("필드 세팅 실패(ASCII도 실패): {} value='{}'", f.getFullyQualifiedName(), safe, e3);
                }
            } catch (Exception e) {
                log.error("setValue {} error: {}", f.getFullyQualifiedName(), e.getMessage(), e);
            }
        }
    }

    private void fillFieldsLoosely(PDAcroForm form, Certificate c) {
        setTextToAll(form, "certNumber",                  c.getCertNumber());
        setTextToAll(form, "issueDate_es_:date",          formatDateKR(c.getIssueDate()));
        setTextToAll(form, "expireDate_es_:date",         formatDateKR(c.getExpireDate()));
        setTextToAll(form, "inspectDate_es_:date",        formatDateKR(c.getInspectDate()));
        setTextToAll(form, "manu_es_:fullname",           c.getManufacturer());
        setTextToAll(form, "modelName",                   c.getModelName());
        setTextToAll(form, "vin",                         c.getVin());
        setTextToAll(form, "manufactureYear_es_:date",    formatNumber(c.getManufactureYear()));
        setTextToAll(form, "firstRegisterDate_es_:date",  formatDateKR(c.getFirstRegisterDate()));
        setTextToAll(form, "mileage",                     c.getMileage() != null ? c.getMileage() + " km" : "");
        setTextToAll(form, "corpName_es_:fullname",       c.getIssuedBy());
        setTextToAll(form, "inspectorCode",               c.getInspectorCode());
        setTextToAll(form, "inspectorName_es_:fullname",  c.getInspectorName());
        // 주의: 서명 필드(Signature...)에는 값 세팅 금지
    }

    private String formatDateKR(LocalDate d) {
        return d == null ? "" : d.format(DF_KR);
    }

    private String formatNumber(Number n) {
        return n == null ? "" : n.toString();
    }
}
