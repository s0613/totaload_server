package com.isoplatform.api.certification;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Entity
@Table(name = "vehicle")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Vehicle {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "qload_user", nullable = false, length = 191)
    private String qloadUser;

    @Column(name = "vin", nullable = false, length = 191)
    private String vin;

    @Column(name = "plate_number", nullable = false, length = 191)
    private String plateNumber;

    @Column(name = "model", nullable = false, length = 191)
    private String model;

    @Column(name = "year")
    private Integer year;

    @Column(name = "driven_distance", nullable = false)
    private Integer drivenDistance;

    @Enumerated(EnumType.STRING)
    @Column(name = "fuel_type", nullable = false)
    private FuelType fuelType;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public enum FuelType {
        GASOLINE, DIESEL, LPG
    }
}
