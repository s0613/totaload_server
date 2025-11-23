package com.isoplatform.api.inspection.service;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.repository.PhotoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * Service for handling photo uploads and retrieval.
 *
 * <h3>Transaction Atomicity Trade-off</h3>
 * <p>
 * Photo upload involves two fundamentally different operations:
 * <ol>
 *   <li>File I/O: Saving the file to disk (not transactional)</li>
 *   <li>Database: Saving metadata to DB (transactional)</li>
 * </ol>
 * </p>
 * <p>
 * These operations cannot be truly atomic because file systems don't participate
 * in database transactions. We handle this pragmatically:
 * </p>
 * <ul>
 *   <li>File is saved first (fail fast on disk issues)</li>
 *   <li>If DB save fails, file remains on disk (orphaned)</li>
 *   <li>Orphaned files are logged for cleanup by a periodic job</li>
 *   <li>We do NOT delete the file on DB failure because:
 *     <ul>
 *       <li>The file might be needed for manual recovery</li>
 *       <li>Delete operation could also fail, adding complexity</li>
 *       <li>A cleanup job is more reliable than catch-block deletion</li>
 *     </ul>
 *   </li>
 * </ul>
 * <p>
 * <strong>Recommendation:</strong> Implement a scheduled job to scan for orphaned
 * files (files on disk without DB records) and clean them up periodically.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class PhotoService {

    private final PhotoRepository photoRepository;

    @Value("${app.storage.photos-path:./storage/photos/}")
    private String photosStoragePath;

    /**
     * Upload a photo file and save metadata to database.
     *
     * <p>
     * This method intentionally does NOT use @Transactional because file I/O
     * cannot participate in database transactions. Instead, we handle errors
     * explicitly and document the failure scenarios.
     * </p>
     *
     * @param file      The multipart file to upload
     * @param vin       Vehicle Identification Number
     * @param category  Photo category (A, B, C, D, E)
     * @param itemCode  Item code within category (A1, A2, B1, etc.)
     * @return The saved Photo entity with generated ID
     * @throws IllegalArgumentException if file validation fails
     * @throws RuntimeException if file I/O or DB save fails
     */
    public Photo uploadPhoto(MultipartFile file, String vin, String category, String itemCode) {
        validateFile(file);

        // Generate unique filename to avoid collisions
        String originalFilename = file.getOriginalFilename();
        String extension = getFileExtension(originalFilename);
        String uniqueFilename = String.format("%s_%s_%s_%s%s",
                vin, category, itemCode, UUID.randomUUID().toString(), extension);

        Path destinationPath = null;

        try {
            // Step 1: Save file to storage (File I/O - not transactional)
            destinationPath = saveFileToStorage(file, uniqueFilename);
            log.debug("파일 저장 완료: {}", destinationPath);

            // Step 2: Create and save Photo entity to database
            Photo photo = Photo.builder()
                    .vin(vin)
                    .category(category)
                    .itemCode(itemCode)
                    .fileName(uniqueFilename)
                    .storagePath(destinationPath.toString())
                    .fileSize(file.getSize())
                    .contentType(file.getContentType())
                    .uploadedAt(LocalDateTime.now())
                    .build();

            Photo saved = photoRepository.save(photo);
            log.info("사진 업로드 완료 - VIN: {}, Category: {}, ItemCode: {}, File: {}",
                    vin, category, itemCode, uniqueFilename);

            return saved;

        } catch (IOException e) {
            // File I/O failed - no cleanup needed since file wasn't saved
            log.error("사진 저장 실패 (파일 I/O 오류) - VIN: {}, Category: {}, Error: {}",
                    vin, category, e.getMessage(), e);
            throw new RuntimeException("사진 저장 중 오류 발생: " + e.getMessage());

        } catch (DataIntegrityViolationException e) {
            // DB save failed AFTER file was successfully saved
            // File is now orphaned on disk - log for cleanup job
            log.error("사진 DB 저장 실패 - VIN: {}, Category: {}, Error: {}",
                    vin, category, e.getMessage(), e);
            log.warn("ORPHANED_FILE: 파일은 저장되었으나 DB 저장 실패로 고아 파일 발생 - " +
                    "파일 경로: {}, VIN: {}, 수동 정리 또는 정리 작업 필요",
                    destinationPath, vin);

            // Provide user-friendly error message
            // Note: We intentionally do NOT delete the file here because:
            // 1. The file might be needed for manual recovery or debugging
            // 2. Delete operation could also fail, complicating error handling
            // 3. A periodic cleanup job is more reliable for orphan management
            throw new RuntimeException(
                    "사진 정보 DB 저장 실패. 시스템 관리자에게 문의하세요. (파일: " + uniqueFilename + ")");
        }
    }

    /**
     * Save the multipart file to storage directory.
     *
     * @param file           The file to save
     * @param uniqueFilename The unique filename to use
     * @return Path to the saved file
     * @throws IOException if file cannot be saved
     */
    private Path saveFileToStorage(MultipartFile file, String uniqueFilename) throws IOException {
        // Create storage directory if not exists
        File storageDir = new File(photosStoragePath);
        if (!storageDir.exists()) {
            boolean created = storageDir.mkdirs();
            if (!created && !storageDir.exists()) {
                throw new IOException("저장 디렉토리 생성 실패: " + photosStoragePath);
            }
        }

        // Save file with REPLACE_EXISTING to handle unlikely filename collisions
        Path destinationPath = Paths.get(photosStoragePath, uniqueFilename);
        Files.copy(
            file.getInputStream(),
            destinationPath,
            StandardCopyOption.REPLACE_EXISTING
        );

        return destinationPath;
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
