package com.isoplatform.api.accident.service;

import com.isoplatform.api.accident.AccidentHistory;
import com.isoplatform.api.accident.repository.AccidentHistoryRepository;
import com.isoplatform.api.accident.request.AccidentHistoryRequest;
import com.isoplatform.api.accident.response.AccidentHistoryResponse;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class AccidentHistoryService {

    private final AccidentHistoryRepository repository;

    @Transactional
    public AccidentHistoryResponse create(AccidentHistoryRequest request, Long userId) {
        AccidentHistory entity = AccidentHistory.builder()
                .vin(request.getVin())
                .accidentType(request.getAccidentType())
                .accidentDate(request.getAccidentDate())
                .repaired(request.isRepaired())
                .remarks(request.getRemarks())
                .registeredBy(userId)
                .build();

        AccidentHistory saved = repository.save(entity);
        log.info("사고 이력 등록: VIN={}, ID={}", saved.getVin(), saved.getId());
        return AccidentHistoryResponse.from(saved);
    }

    @Transactional(readOnly = true)
    public List<AccidentHistoryResponse> getByVin(String vin) {
        return repository.findByVinOrderByAccidentDateDesc(vin)
                .stream()
                .map(AccidentHistoryResponse::from)
                .collect(Collectors.toList());
    }

    @Transactional(readOnly = true)
    public AccidentHistoryResponse getById(Long id) {
        AccidentHistory entity = repository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("사고 이력을 찾을 수 없습니다: " + id));
        return AccidentHistoryResponse.from(entity);
    }

    @Transactional
    public AccidentHistoryResponse update(Long id, AccidentHistoryRequest request, Long userId) {
        AccidentHistory entity = repository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("사고 이력을 찾을 수 없습니다: " + id));

        if (!entity.getRegisteredBy().equals(userId)) {
            throw new IllegalStateException("본인이 등록한 이력만 수정할 수 있습니다");
        }

        // VIN은 차량 식별자이므로 수정 불가
        entity.setAccidentType(request.getAccidentType());
        entity.setAccidentDate(request.getAccidentDate());
        entity.setRepaired(request.isRepaired());
        entity.setRemarks(request.getRemarks());

        log.info("사고 이력 수정: ID={}", id);
        return AccidentHistoryResponse.from(entity);
    }

    @Transactional
    public void delete(Long id, Long userId) {
        AccidentHistory entity = repository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("사고 이력을 찾을 수 없습니다: " + id));

        if (!entity.getRegisteredBy().equals(userId)) {
            throw new IllegalStateException("본인이 등록한 이력만 삭제할 수 있습니다");
        }

        repository.deleteById(id);
        log.info("사고 이력 삭제: ID={}", id);
    }
}
