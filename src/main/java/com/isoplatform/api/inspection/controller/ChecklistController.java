package com.isoplatform.api.inspection.controller;

import com.isoplatform.api.inspection.VehicleChecklist;
import com.isoplatform.api.inspection.request.ChecklistSubmissionRequest;
import com.isoplatform.api.inspection.service.ChecklistService;
import com.isoplatform.api.security.ApiKeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/checklists")
@RequiredArgsConstructor
public class ChecklistController {

    private final ChecklistService checklistService;
    private final ApiKeyService apiKeyService;

    @PostMapping("/submit")
    public ResponseEntity<?> submitChecklist(
            @Valid @RequestBody ChecklistSubmissionRequest request,
            @RequestHeader("X-API-KEY") String apiKey) {

        log.info("체크리스트 제출 요청 - VIN: {}, 항목 수: {}", request.getVin(), request.getItems().size());

        // API key validation
        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            log.warn("체크리스트 제출 실패 - 인증 실패: {}", validationResult.getMessage());
            return ResponseEntity.status(401).body("Unauthorized: " + validationResult.getMessage());
        }

        try {
            VehicleChecklist checklist = checklistService.submitChecklist(request);

            Map<String, Object> response = new HashMap<>();
            response.put("id", checklist.getId());
            response.put("vin", checklist.getVin());
            response.put("vehicleNumber", checklist.getVehicleNumber());
            response.put("totalScore", checklist.getTotalScore());
            response.put("maxTotalScore", checklist.getMaxTotalScore());
            response.put("status", checklist.getStatus());
            response.put("createdAt", checklist.getCreatedAt().toString());
            response.put("itemCount", checklist.getItems().size());

            return ResponseEntity.ok(response);

        } catch (IllegalArgumentException e) {
            log.warn("체크리스트 제출 실패 - 유효성 검사 실패: {}", e.getMessage());
            return ResponseEntity.badRequest().body(e.getMessage());
        } catch (Exception e) {
            log.error("체크리스트 제출 실패", e);
            return ResponseEntity.internalServerError().body("체크리스트 제출 실패: " + e.getMessage());
        }
    }

    @GetMapping("/vin/{vin}")
    public ResponseEntity<?> getChecklistByVin(
            @PathVariable String vin,
            @RequestHeader("X-API-KEY") String apiKey) {

        ApiKeyService.ApiKeyValidationResult validationResult = apiKeyService.validateApiKeyWithDetails(apiKey);
        if (!validationResult.isValid()) {
            return ResponseEntity.status(401).build();
        }

        try {
            VehicleChecklist checklist = checklistService.getChecklistByVin(vin);
            return ResponseEntity.ok(checklist);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.notFound().build();
        }
    }
}
