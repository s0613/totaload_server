package com.isoplatform.api.util;

import com.isoplatform.api.certification.Certificate;
import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType0Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.*;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

@Slf4j
@Component
public class PDFParser {

    private static final String TEMPLATE_PDF = "static/ISO_acrobat07.pdf";

    // TTF 우선(가장 안정적), 필요시 예비 후보
    private static final String[] FONT_CANDIDATES = new String[] {
            "static/fonts/NotoSansKR-Light.ttf",
            "static/fonts/NotoSansKR-Regular.ttf",
            "static/fonts/NanumGothic.ttf",
            "static/fonts/NotoSansCJKkr-Regular.otf"
    };

    private static final String FONT_RESOURCE_NAME = "NotoSansKR-Light";
    private static final DateTimeFormatter DF_KR = DateTimeFormatter.ofPattern("yyyy년 MM월 dd일");

    public String createCertificatePdf(Certificate c) throws Exception {
        Path outDir = Paths.get("certificates");
        Files.createDirectories(outDir);
        String outFile = outDir.resolve(c.getCertNumber() + ".pdf").toString();

        // 템플릿 로드
        ClassPathResource cpr = new ClassPathResource(TEMPLATE_PDF);
        if (!cpr.exists()) throw new IllegalStateException("템플릿을 찾을 수 없습니다: " + TEMPLATE_PDF);
        byte[] templateBytes;
        try (InputStream in = cpr.getInputStream()) {
            templateBytes = in.readAllBytes();
        }

        try (PDDocument doc = Loader.loadPDF(templateBytes)) {
            PDAcroForm form = ensureAcroFormReady(doc);

            // 폰트 임베딩 (서브셋팅 false: 전체 임베딩)
            PDFont font = loadKoreanFontRobust(doc);

            // DR/페이지 리소스 등록
            PDResources dr = form.getDefaultResources();
            COSName fontKey = COSName.getPDFName(FONT_RESOURCE_NAME);
            dr.put(fontKey, font);
            for (PDPage page : doc.getPages()) {
                PDResources pr = page.getResources();
                if (pr == null) { pr = new PDResources(); page.setResources(pr); }
                pr.put(fontKey, font);
            }

            // 전역 DA
            final String da = "/" + FONT_RESOURCE_NAME + " 10 Tf 0 g";
            form.setDefaultAppearance(da);

            // 모든 텍스트 필드: DA 통일, 리치텍스트 off, 기존 AP 제거
            for (PDField f : form.getFieldTree()) {
                if (f instanceof PDTextField tf) {
                    tf.setDefaultAppearance(da);
                    tf.setRichText(false);
                    for (PDAnnotationWidget w : tf.getWidgets()) {
                        PDAppearanceDictionary ap = w.getAppearance();
                        if (ap != null) w.setAppearance(null);
                    }
                }
            }

            // ========= 값 채우기 (템플릿 실제 필드에 맞춘 후보 매핑) =========
            // 발급/검증
            setTextToAny(form, new String[]{"certNumber"}, c.getCertNumber());
            setTextToAny(form, new String[]{"issueDate"}, formatDateKR(c.getIssueDate()));
            setTextToAny(form, new String[]{"inspectDate"}, formatDateKR(c.getInspectDate()));
            setTextToAny(form, new String[]{"inspectorName"}, c.getInspectorName());
            setTextToAny(form, new String[]{"inspectorCode"}, c.getInspectorCode());

            // 템플릿에는 inspectCountry가 없고 inspectCount만 있음(오탈자 보정)
            setTextToAny(form, new String[]{"inspectCountry","inspectCount"}, c.getInspectCountry());

            // 템플릿에 없음 → 경고만
            warnIfMissing(form, "inspectSite");
            warnIfMissing(form, "eVerifyId");
            warnIfMissing(form, "verifyUrl");
            warnIfMissing(form, "disclaimer");

            // 차량 식별
            setTextToAny(form, new String[]{"manufacturer"}, c.getManufacturer());
            setTextToAny(form, new String[]{"modelName"}, c.getModelName());
            setTextToAny(form, new String[]{"vin"}, c.getVin());

            // manufactureYear는 템플릿에 없고 manuYear만 존재 → 보정
            String manuYearStr = c.getManuYear() != null ? c.getManuYear().toString()
                    : (c.getManufactureYear() != null ? c.getManufactureYear().toString() : "");
            setTextToAny(form, new String[]{"manuYear"}, manuYearStr);

            setTextToAny(form, new String[]{"firstRegisterDate"}, formatDateKR(c.getFirstRegisterDate()));
            setTextToAny(form, new String[]{"mileage"}, c.getMileage() == null ? "" : c.getMileage() + " km");
            setTextToAny(form, new String[]{"variant"}, c.getVariant());

            // engineDisplacement vs displacement → 템플릿에는 displacement만 있음
            setTextToAny(form, new String[]{"displacement"}, or(c.getDisplacement(), c.getEngineDisplacement()));

            setTextToAny(form, new String[]{"seatCount"}, toStr(c.getSeatCount()));
            setTextToAny(form, new String[]{"fuelType"}, c.getFuelType());
            setTextToAny(form, new String[]{"driveType"}, c.getDriveType());

            // 템플릿에 없음 → 경고만
            warnIfMissing(form, "engineNumber");
            warnIfMissing(form, "modelYear");
            warnIfMissing(form, "usecase");
            warnIfMissing(form, "colorCode");
            warnIfMissing(form, "doorCount");
            warnIfMissing(form, "odoType");

            // 치수·중량
            setTextToAny(form, new String[]{"length"}, c.getLength());
            setTextToAny(form, new String[]{"width"}, c.getWidth());
            setTextToAny(form, new String[]{"height"}, c.getHeight());
            setTextToAny(form, new String[]{"wheelbase"}, c.getWheelbase());
            setTextToAny(form, new String[]{"trackFront"}, c.getTrackFront());
            setTextToAny(form, new String[]{"gvm"}, c.getGvm());
            setTextToAny(form, new String[]{"curbWeight"}, c.getCurbWeight());
            setTextToAny(form, new String[]{"axleFront"}, c.getAxleFront());
            // 템플릿에 axleRear 없음 → 경고
            warnIfMissing(form, "axleRear");

            // bodyType ↔ bobyType(템플릿 오탈자) → 보정
            setTextToAny(form, new String[]{"bodyType","bobyType"}, c.getBodyType());

            // 파워트레인·배출
            setTextToAny(form, new String[]{"engineType"}, c.getEngineType());
            setTextToAny(form, new String[]{"cylinderCount"}, toStr(c.getCylinderCount()));
            setTextToAny(form, new String[]{"induction"}, c.getInduction());
            setTextToAny(form, new String[]{"enginePower"}, c.getEnginePower());
            setTextToAny(form, new String[]{"emissionStd"}, c.getEmissionStd());
            setTextToAny(form, new String[]{"motorPower"}, c.getMotorPower());
            setTextToAny(form, new String[]{"batteryVoltage"}, c.getBatteryVoltage());
            setTextToAny(form, new String[]{"transmission"}, c.getTransmission());
            setTextToAny(form, new String[]{"brakeType"}, c.getBrakeType());
            setTextToAny(form, new String[]{"fuelEconomy"}, c.getFuelEconomy());

            // 등급/결함
            setTextToAny(form, new String[]{"jaaiGrade"}, c.getJaaiGrade());
            setTextToAny(form, new String[]{"aisScore"}, c.getAisScore());
            setTextToAny(form, new String[]{"repairHistory"}, c.getRepairHistory());
            setTextToAny(form, new String[]{"comment"}, c.getComment());

            // 수입국 규정
            setTextToAny(form, new String[]{"destinationCountry"}, c.getDestinationCountry());
            setTextToAny(form, new String[]{"validityNote"}, c.getValidityNote());

            // 항균/방사선
            setTextToAny(form, new String[]{"AntiResult"}, c.getRadiationResult());

            // 저장
            doc.save(outFile);
            log.info("PDF 저장 완료: {}", outFile);
        }

        return outFile;
    }

    private PDAcroForm ensureAcroFormReady(PDDocument doc) {
        PDDocumentCatalog catalog = doc.getDocumentCatalog();
        PDAcroForm form = catalog.getAcroForm();
        if (form == null) throw new IllegalStateException("이 PDF에는 AcroForm이 없습니다.");
        form.setNeedAppearances(false);
        if (form.getDefaultResources() == null) form.setDefaultResources(new PDResources());
        return form;
    }

    private PDFont loadKoreanFontRobust(PDDocument doc) throws Exception {
        Exception last = null;
        for (String path : FONT_CANDIDATES) {
            ClassPathResource res = new ClassPathResource(path);
            if (!res.exists()) { log.warn("폰트 없음: {}", path); continue; }
            try (InputStream is = res.getInputStream()) {
                byte[] bytes = is.readAllBytes();
                if (bytes.length == 0) { log.warn("빈 폰트 파일: {}", path); continue; }
                log.info("폰트 로드 시도: {} ({} bytes)", path, bytes.length);
                PDFont f = PDType0Font.load(doc, new java.io.ByteArrayInputStream(bytes), false);
                log.info("폰트 로드 성공: {}", path);
                return f;
            } catch (Exception e) {
                String msg = e.getMessage() == null ? "" : e.getMessage();
                log.warn("폰트 로드 실패: {} ({})", path, msg);
                last = e;
            }
        }
        throw new IllegalStateException("사용 가능한 한글 폰트를 로드하지 못했습니다. TTF 정식 풀셋을 우선 배치하세요.", last);
    }

    private void setTextToAny(PDAcroForm form, String[] candidateNames, String value) {
        String safe = value == null ? "" : value;
        for (String name : candidateNames) {
            PDField f = form.getField(name);
            if (f != null) {
                try {
                    if (f instanceof PDTextField tf) tf.setValue(safe);
                    else f.setValue(safe);
                    log.debug("필드 세팅: {} ← '{}'", name, safe);
                    return;
                } catch (Exception e) {
                    log.error("필드 '{}' 값 세팅 실패: {}", name, e.getMessage(), e);
                    return;
                }
            }
        }
        log.warn("매핑 실패(템플릿에 없음): {}", Arrays.toString(candidateNames));
    }

    private void warnIfMissing(PDAcroForm form, String name) {
        if (form.getField(name) == null) {
            log.warn("템플릿에 필드가 없습니다: {}", name);
        }
    }

    private String formatDateKR(LocalDate d) { return d == null ? "" : d.format(DF_KR); }
    private String toStr(Number n) { return n == null ? "" : n.toString(); }
    private String or(String a, String b) { return (a != null && !a.isEmpty()) ? a : (b == null ? "" : b); }
}
