package com.isoplatform.api.inspection.controller;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.service.PhotoService;
import com.isoplatform.api.security.ApiKeyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/photos")
@RequiredArgsConstructor
public class PhotoController {

    private final PhotoService photoService;
    private final ApiKeyService apiKeyService;

    @PostMapping("/upload")
    public ResponseEntity<?> uploadPhoto(
            @RequestParam("file") MultipartFile file,
            @RequestParam("vin") String vin,
            @RequestParam("category") String category,
            @RequestParam("itemCode") String itemCode,
            @RequestHeader("X-API-KEY") String apiKey) {

        log.info("사진 업로드 요청 - VIN: {}, Category: {}, ItemCode: {}", vin, category, itemCode);

        // API key validation
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            log.warn("사진 업로드 실패 - 인증 실패: {}", validationResult.getMessage());
            return ResponseEntity.status(401).body("Unauthorized: " + validationResult.getMessage());
        }

        try {
            Photo photo = photoService.uploadPhoto(file, vin, category, itemCode);

            Map<String, Object> response = new HashMap<>();
            response.put("id", photo.getId());
            response.put("fileName", photo.getFileName());
            response.put("storagePath", photo.getStoragePath());
            response.put("fileSize", photo.getFileSize());
            response.put("uploadedAt", photo.getUploadedAt().toString());

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("사진 업로드 실패 - 유효성 검사 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("사진 업로드 실패", e);
            return ResponseEntity.internalServerError().body("사진 업로드 실패: " + e.getMessage());
        }
    }

    @GetMapping("/vin/{vin}")
    public ResponseEntity<List<Photo>> getPhotosByVin(
            @PathVariable String vin,
            @RequestHeader("X-API-KEY") String apiKey) {

        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        List<Photo> photos = photoService.getPhotosByVin(vin);
        return ResponseEntity.ok(photos);
    }
}
