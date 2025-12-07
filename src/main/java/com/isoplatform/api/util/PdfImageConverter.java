package com.isoplatform.api.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.rendering.PDFRenderer;
import org.springframework.stereotype.Component;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * PDF → Image 변환 유틸리티
 * - PDFBox 3.0.1+ 사용
 * - 업로드된 PDF를 페이지별 이미지로 변환하여 AI 분석에 사용
 */
@Slf4j
@Component
public class PdfImageConverter {

    /**
     * PDF 파일을 페이지별 이미지로 변환
     *
     * @param pdfPath PDF 파일 경로
     * @return 변환된 이미지 파일 경로 리스트
     */
    public List<String> convertPdfToImages(String pdfPath) throws IOException {
        List<String> imagePaths = new ArrayList<>();
        File pdfFile = new File(pdfPath);

        if (!pdfFile.exists()) {
            throw new IOException("PDF 파일을 찾을 수 없습니다: " + pdfPath);
        }

        try (PDDocument document = Loader.loadPDF(pdfFile)) {
            PDFRenderer renderer = new PDFRenderer(document);
            int pageCount = document.getNumberOfPages();

            log.info("PDF 이미지 변환 시작: {} (총 {}페이지)", pdfPath, pageCount);

            // 임시 디렉토리 생성
            Path tempDir = Files.createTempDirectory("pdf-images-");

            for (int i = 0; i < pageCount; i++) {
                // 300 DPI로 렌더링 (AI 분석에 충분한 품질)
                BufferedImage image = renderer.renderImageWithDPI(i, 300);

                // 이미지 파일 저장
                String imagePath = tempDir.resolve("page-" + (i + 1) + ".png").toString();
                ImageIO.write(image, "PNG", new File(imagePath));
                imagePaths.add(imagePath);

                log.debug("페이지 {} 변환 완료: {}", i + 1, imagePath);
            }

            log.info("PDF 이미지 변환 완료: {} → {} 이미지", pdfPath, imagePaths.size());
        }

        return imagePaths;
    }

    /**
     * 임시 이미지 파일들 삭제
     *
     * @param imagePaths 삭제할 이미지 파일 경로 리스트
     */
    public void cleanupImages(List<String> imagePaths) {
        for (String imagePath : imagePaths) {
            try {
                Files.deleteIfExists(Path.of(imagePath));
                log.debug("임시 이미지 삭제: {}", imagePath);
            } catch (IOException e) {
                log.warn("임시 이미지 삭제 실패: {}", imagePath, e);
            }
        }

        // 임시 디렉토리도 삭제 시도
        if (!imagePaths.isEmpty()) {
            try {
                Path tempDir = Path.of(imagePaths.get(0)).getParent();
                if (tempDir != null && Files.exists(tempDir)) {
                    Files.delete(tempDir);
                    log.debug("임시 디렉토리 삭제: {}", tempDir);
                }
            } catch (IOException e) {
                log.warn("임시 디렉토리 삭제 실패", e);
            }
        }
    }
}
