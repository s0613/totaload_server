package com.isoplatform.api.inspection.controller;

import com.isoplatform.api.inspection.Photo;
import com.isoplatform.api.inspection.service.PhotoService;
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

    @PostMapping("/upload")
    public ResponseEntity<?> uploadPhoto(
            @RequestParam("file") MultipartFile file,
            @RequestParam("vin") String vin,
            @RequestParam("category") String category,
            @RequestParam("itemCode") String itemCode) {

        log.info("사진 업로드 요청 - VIN: {}, Category: {}, ItemCode: {}", vin, category, itemCode);

        try {
            Photo photo = photoService.uploadPhoto(file, vin, category, itemCode);

            Map<String, Object> response = new HashMap<>();
            response.put("id", photo.getId());
            response.put("fileName", photo.getFileName());
            response.put("storagePath", photo.getStoragePath());
            response.put("cloudFrontUrl", photo.getCloudFrontUrl());
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
    public ResponseEntity<List<Photo>> getPhotosByVin(@PathVariable String vin) {
        List<Photo> photos = photoService.getPhotosByVin(vin);
        return ResponseEntity.ok(photos);
    }
}
