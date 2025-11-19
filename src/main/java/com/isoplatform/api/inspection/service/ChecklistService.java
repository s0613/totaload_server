package com.isoplatform.api.inspection.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.inspection.ChecklistItem;
import com.isoplatform.api.inspection.VehicleChecklist;
import com.isoplatform.api.inspection.repository.VehicleChecklistRepository;
import com.isoplatform.api.inspection.request.ChecklistSubmissionRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class ChecklistService {

    private final VehicleChecklistRepository checklistRepository;
    private final ObjectMapper objectMapper;

    @Transactional
    public VehicleChecklist submitChecklist(ChecklistSubmissionRequest request) {
        // Check for duplicate VIN
        checklistRepository.findByVin(request.getVin()).ifPresent(existing -> {
            throw new IllegalArgumentException("이미 해당 VIN으로 체크리스트가 제출되었습니다: " + request.getVin());
        });

        // Convert vehicle info to JSON
        String vehicleInfoJson;
        try {
            vehicleInfoJson = objectMapper.writeValueAsString(request.getVehicleInfo());
        } catch (JsonProcessingException e) {
            throw new RuntimeException("차량 정보 JSON 변환 실패", e);
        }

        // Create checklist
        VehicleChecklist checklist = VehicleChecklist.builder()
                .vehicleNumber(request.getVehicleNumber())
                .vin(request.getVin())
                .vehicleInfoJson(vehicleInfoJson)
                .createdAt(LocalDateTime.now())
                .status(request.getStatus())
                .build();

        if ("completed".equals(request.getStatus())) {
            checklist.setCompletedAt(LocalDateTime.now());
        }

        // Add items
        for (ChecklistSubmissionRequest.ChecklistItemData itemData : request.getItems()) {
            ChecklistItem item = ChecklistItem.builder()
                    .code(itemData.getCode())
                    .category(itemData.getCategory())
                    .item(itemData.getItem())
                    .detailedCriteria(itemData.getDetailedCriteria())
                    .maxScore(itemData.getMaxScore())
                    .score(itemData.getScore())
                    .evidence(itemData.getEvidence())
                    .remarks(itemData.getRemarks())
                    .build();

            checklist.addItem(item);
        }

        // Calculate scores
        checklist.calculateScores();

        VehicleChecklist saved = checklistRepository.save(checklist);
        log.info("체크리스트 제출 완료 - VIN: {}, 총점: {}/{}, 항목 수: {}",
                saved.getVin(), saved.getTotalScore(), saved.getMaxTotalScore(), saved.getItems().size());

        return saved;
    }

    public VehicleChecklist getChecklistByVin(String vin) {
        return checklistRepository.findByVin(vin)
                .orElseThrow(() -> new IllegalArgumentException("체크리스트를 찾을 수 없습니다: " + vin));
    }

    public VehicleChecklist getChecklistById(Long id) {
        return checklistRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("체크리스트를 찾을 수 없습니다: " + id));
    }
}
