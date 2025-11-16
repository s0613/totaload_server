package com.isoplatform.api.certification.repository;

import com.isoplatform.api.certification.Certificate;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface CertificateRepository extends JpaRepository<Certificate, Long> {

    Optional<Certificate> findByVin(String vin);
    Optional<Certificate> findByCertNumber(String certNumber);
    boolean existsByVin(String vin);
    List<Certificate> findByCertNumberStartingWith(String prefix);

    // 발급자별 조회 메서드 추가 (iso-server 통합)
    List<Certificate> findByIssuerUserId(Long issuerUserId);
    List<Certificate> findByIssuerUserIdIsNotNull();
    List<Certificate> findByIssuedBy(String issuedBy);

    // N+1 문제 해결을 위한 Join Query 추가 (iso-server 통합)
    @Query("SELECT DISTINCT c FROM Certificate c LEFT JOIN FETCH c.issuerUserIds WHERE :issuerUserId MEMBER OF c.issuerUserIds")
    List<Certificate> findByIssuerUserIdWithFetch(@Param("issuerUserId") Long issuerUserId);

    // 모든 인증서를 발급자 정보와 함께 조회 (N+1 문제 해결) (iso-server 통합)
    @Query("SELECT DISTINCT c FROM Certificate c LEFT JOIN FETCH c.issuerUserIds")
    List<Certificate> findAllWithIssuers();
}
