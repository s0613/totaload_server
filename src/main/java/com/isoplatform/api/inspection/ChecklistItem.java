package com.isoplatform.api.inspection;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "checklist_items")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ChecklistItem {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "checklist_id", nullable = false)
    private VehicleChecklist checklist;

    @Column(nullable = false)
    private String code; // A1, A2, B1, etc.

    @Column(nullable = false)
    private String category; // A, B, C, D, E

    @Column(nullable = false)
    private String item; // 항목명

    private String detailedCriteria; // 세부 기준

    @Column(nullable = false)
    private Integer maxScore;

    @Column(nullable = false)
    private Integer score;

    @Column(columnDefinition = "TEXT")
    private String evidence; // 증빙 자료

    @Column(columnDefinition = "TEXT")
    private String remarks; // 비고
}
