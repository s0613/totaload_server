package com.isoplatform.api.inspection.service;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.repository.PhotoRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class PhotoService {

    private final PhotoRepository photoRepository;

    @Value("${app.storage.photos-path:./storage/photos/}")
    private String photosStoragePath;

    @Transactional
    public Photo uploadPhoto(MultipartFile file, String vin, String category, String itemCode) {
        validateFile(file);

        try {
            // Generate unique filename
            String originalFilename = file.getOriginalFilename();
            String extension = getFileExtension(originalFilename);
            String uniqueFilename = String.format("%s_%s_%s_%s%s",
                    vin, category, itemCode, UUID.randomUUID().toString(), extension);

            // Create storage directory if not exists
            File storageDir = new File(photosStoragePath);
            if (!storageDir.exists()) {
                storageDir.mkdirs();
            }

            // Save file to storage
            Path destinationPath = Paths.get(photosStoragePath, uniqueFilename);
            Files.copy(file.getInputStream(), destinationPath);

            // Create Photo entity
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
            log.error("사진 업로드 실패 - VIN: {}, Category: {}", vin, category, e);
            throw new RuntimeException("사진 저장 중 오류 발생: " + e.getMessage());
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

        String contentType = file.getContentType();
        if (contentType == null || (!contentType.startsWith("image/"))) {
            throw new IllegalArgumentException("이미지 파일만 업로드 가능합니다.");
        }

        // Max 10MB
        if (file.getSize() > 10 * 1024 * 1024) {
            throw new IllegalArgumentException("파일 크기는 10MB를 초과할 수 없습니다.");
        }
    }

    private String getFileExtension(String filename) {
        if (filename == null || !filename.contains(".")) {
            return ".jpg";
        }
        return filename.substring(filename.lastIndexOf("."));
    }
}
