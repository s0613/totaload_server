package com.isoplatform.api.inspection.service;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.repository.PhotoRepository;
import com.isoplatform.api.storage.S3Service;
import com.isoplatform.api.util.S3UploadResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Service for handling photo uploads and retrieval.
 *
 * <h3>S3 Storage Integration</h3>
 * <p>
 * Photos are uploaded to S3 and served via CloudFront CDN.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PhotoService {

    private final PhotoRepository photoRepository;
    private final S3Service s3Service;

    private static final String S3_PHOTOS_FOLDER = "photos";

    /**
     * Upload a photo file to S3 and save metadata to database.
     *
     * @param file      The multipart file to upload
     * @param vin       Vehicle Identification Number
     * @param category  Photo category (A, B, C, D, E)
     * @param itemCode  Item code within category (A1, A2, B1, etc.)
     * @return The saved Photo entity with generated ID
     * @throws IllegalArgumentException if file validation fails
     * @throws RuntimeException if upload or DB save fails
     */
    public Photo uploadPhoto(MultipartFile file, String vin, String category, String itemCode) {
        validateFile(file);

        // Generate unique filename to avoid collisions
        String originalFilename = file.getOriginalFilename();
        String extension = getFileExtension(originalFilename);
        String uniqueFilename = String.format("%s_%s_%s_%s%s",
                vin, category, itemCode, UUID.randomUUID().toString(), extension);

        S3UploadResult uploadResult = null;

        try {
            // Step 1: Upload file to S3
            uploadResult = s3Service.uploadFile(file, S3_PHOTOS_FOLDER, uniqueFilename);
            log.debug("S3 업로드 완료: {}", uploadResult.getCloudFrontUrl());

            // Step 2: Create and save Photo entity to database
            Photo photo = Photo.builder()
                    .vin(vin)
                    .category(category)
                    .itemCode(itemCode)
                    .fileName(uniqueFilename)
                    .storagePath(uploadResult.getS3Key())
                    .cloudFrontUrl(uploadResult.getCloudFrontUrl())
                    .fileSize(file.getSize())
                    .contentType(file.getContentType())
                    .uploadedAt(LocalDateTime.now())
                    .build();

            Photo saved = photoRepository.save(photo);
            log.info("사진 업로드 완료 - VIN: {}, Category: {}, ItemCode: {}, CloudFront: {}",
                    vin, category, itemCode, uploadResult.getCloudFrontUrl());

            return saved;

        } catch (IOException e) {
            // S3 upload failed
            log.error("사진 S3 업로드 실패 - VIN: {}, Category: {}, Error: {}",
                    vin, category, e.getMessage(), e);
            throw new RuntimeException("사진 업로드 중 오류 발생: " + e.getMessage());

        } catch (DataIntegrityViolationException e) {
            // DB save failed AFTER file was successfully uploaded to S3
            log.error("사진 DB 저장 실패 - VIN: {}, Category: {}, Error: {}",
                    vin, category, e.getMessage(), e);

            // Try to cleanup S3 file
            if (uploadResult != null) {
                try {
                    s3Service.deleteFile(uploadResult.getS3Key());
                    log.info("S3 파일 정리 완료: {}", uploadResult.getS3Key());
                } catch (Exception deleteEx) {
                    log.warn("ORPHANED_FILE: S3 파일 삭제 실패 - key: {}, VIN: {}",
                            uploadResult.getS3Key(), vin);
                }
            }

            throw new RuntimeException(
                    "사진 정보 DB 저장 실패. 시스템 관리자에게 문의하세요. (파일: " + uniqueFilename + ")");
        }
    }

    public List<Photo> getPhotosByVin(String vin) {
        return photoRepository.findByVin(vin);
    }

    public List<Photo> getPhotosByChecklistId(Long checklistId) {
        return photoRepository.findByChecklistId(checklistId);
    }

    private void validateFile(MultipartFile file) {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("파일이 비어있습니다.");
        }

        // Whitelist allowed image formats (reject SVG, BMP, and other unsafe/unintended formats)
        String contentType = file.getContentType();
        Set<String> allowedTypes = Set.of(
            "image/jpeg",
            "image/png",
            "image/webp",
            "image/gif"
        );

        if (contentType == null || !allowedTypes.contains(contentType)) {
            throw new IllegalArgumentException(
                "지원하는 이미지 형식: JPEG, PNG, WebP, GIF"
            );
        }

        // Max 10MB
        long maxSize = 10 * 1024 * 1024;
        if (file.getSize() > maxSize) {
            throw new IllegalArgumentException(
                String.format("파일 크기는 %dMB를 초과할 수 없습니다.", maxSize / (1024 * 1024))
            );
        }
    }

    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return ".jpg";
        }
        return filename.substring(filename.lastIndexOf("."));
    }
}
