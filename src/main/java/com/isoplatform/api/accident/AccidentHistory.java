package com.isoplatform.api.accident;

import jakarta.persistence.*;
import lombok.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "accident_history", indexes = {
    @Index(name = "idx_accident_history_vin", columnList = "vin")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AccidentHistory {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 17)
    private String vin;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AccidentType accidentType;

    @Column(nullable = false)
    private LocalDate accidentDate;

    @Column(nullable = false)
    private boolean repaired;

    @Column(length = 500)
    private String remarks;

    @Column(nullable = false)
    private Long registeredBy;

    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
