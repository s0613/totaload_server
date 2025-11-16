package com.isoplatform.api.auth;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 120)
    private String email;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(nullable = false, length = 255)
    private String password;

    // ✅ NOT NULL 컬럼
    @Column(nullable = false, length = 50)
    private String provider;       // "LOCAL" | "GOOGLE" ...

    // ✅ NOT NULL 컬럼
    @Column(nullable = false, length = 128)
    private String providerId;     // LOCAL: email, GOOGLE: sub

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime updatedAt;

    @Column(nullable = false, length = 255)
    private String company;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 20)
    private Role role;

    @Column(nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    private LocalDateTime lastLoginAt;

    @PrePersist
    public void prePersist() {
        LocalDateTime now = LocalDateTime.now();
        if (this.createdAt == null) this.createdAt = now;
        if (this.updatedAt == null) this.updatedAt = now;

        // ✅ 필수 칼럼 기본값들 보정
        if (this.provider == null || this.provider.isBlank()) this.provider = "LOCAL";
        if (this.providerId == null || this.providerId.isBlank()) this.providerId = this.email;

        if (this.role == null) this.role = Role.USER;
        if (this.company == null || this.company.isBlank()) this.company = "SELF";
        if (this.isActive == null) this.isActive = true;
    }

    @PreUpdate
    public void preUpdate() {
        this.updatedAt = LocalDateTime.now();

        // 보수적 보정
        if (this.provider == null || this.provider.isBlank()) this.provider = "LOCAL";
        if (this.providerId == null || this.providerId.isBlank()) this.providerId = this.email;

        if (this.role == null) this.role = Role.USER;
        if (this.company == null || this.company.isBlank()) this.company = "SELF";
        if (this.isActive == null) this.isActive = true;
    }
}
