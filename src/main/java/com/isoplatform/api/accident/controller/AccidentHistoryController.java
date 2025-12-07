package com.isoplatform.api.accident.controller;

import com.isoplatform.api.accident.request.AccidentHistoryRequest;
import com.isoplatform.api.accident.response.AccidentHistoryResponse;
import com.isoplatform.api.accident.service.AccidentHistoryService;
import com.isoplatform.api.auth.security.CustomUserDetails;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/accident-history")
@RequiredArgsConstructor
public class AccidentHistoryController {

    private final AccidentHistoryService service;

    @PostMapping
    public ResponseEntity<AccidentHistoryResponse> create(
            @Valid @RequestBody AccidentHistoryRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        AccidentHistoryResponse response = service.create(request, userDetails.getUser().getId());
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/vin/{vin}")
    public ResponseEntity<List<AccidentHistoryResponse>> getByVin(@PathVariable String vin) {
        return ResponseEntity.ok(service.getByVin(vin));
    }

    @GetMapping("/{id}")
    public ResponseEntity<AccidentHistoryResponse> getById(@PathVariable Long id) {
        return ResponseEntity.ok(service.getById(id));
    }

    @PutMapping("/{id}")
    public ResponseEntity<AccidentHistoryResponse> update(
            @PathVariable Long id,
            @Valid @RequestBody AccidentHistoryRequest request,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        return ResponseEntity.ok(service.update(id, request, userDetails.getUser().getId()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(
            @PathVariable Long id,
            @AuthenticationPrincipal CustomUserDetails userDetails) {
        service.delete(id, userDetails.getUser().getId());
        return ResponseEntity.noContent().build();
    }
}
