package com.isoplatform.api.inspection;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "vehicle_checklists")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VehicleChecklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String vehicleNumber;

    @Column(nullable = false, unique = true)
    private String vin;

    @Column(columnDefinition = "TEXT")
    private String vehicleInfoJson; // JSON string of vehicle info

    @OneToMany(mappedBy = "checklist", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<ChecklistItem> items = new ArrayList<>();

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime completedAt;

    @Column(nullable = false)
    private String status; // draft, completed, submitted

    private Integer totalScore; // Calculated field

    private Integer maxTotalScore; // Calculated field

    public void addItem(ChecklistItem item) {
        items.add(item);
        item.setChecklist(this);
    }

    public void calculateScores() {
        this.totalScore = items.stream()
                .mapToInt(ChecklistItem::getScore)
                .sum();
        this.maxTotalScore = items.stream()
                .mapToInt(ChecklistItem::getMaxScore)
                .sum();
    }
}
