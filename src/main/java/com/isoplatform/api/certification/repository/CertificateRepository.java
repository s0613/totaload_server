package com.isoplatform.api.certification.repository;

import com.isoplatform.api.certification.Certificate;
import com.isoplatform.api.certification.CertificateStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
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

    // Search by keyword (certNumber, manufacturer, modelName, vin 검색)
    @Query("SELECT c FROM Certificate c WHERE " +
           "LOWER(c.certNumber) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(c.manufacturer) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(c.modelName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
           "LOWER(c.vin) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    List<Certificate> searchByKeyword(@Param("keyword") String keyword);

    // Advanced search
    @Query("SELECT c FROM Certificate c WHERE " +
           "(:certNumber IS NULL OR LOWER(c.certNumber) LIKE LOWER(CONCAT('%', :certNumber, '%'))) AND " +
           "(:manufacturer IS NULL OR LOWER(c.manufacturer) LIKE LOWER(CONCAT('%', :manufacturer, '%'))) AND " +
           "(:modelName IS NULL OR LOWER(c.modelName) LIKE LOWER(CONCAT('%', :modelName, '%'))) AND " +
           "(:vin IS NULL OR LOWER(c.vin) LIKE LOWER(CONCAT('%', :vin, '%'))) AND " +
           "(:country IS NULL OR c.inspectCountry = :country) AND " +
           "(:status IS NULL OR c.status = :status) AND " +
           "(:issueDateFrom IS NULL OR c.issueDate >= :issueDateFrom) AND " +
           "(:issueDateTo IS NULL OR c.issueDate <= :issueDateTo) AND " +
           "(:expireDateFrom IS NULL OR c.expireDate >= :expireDateFrom) AND " +
           "(:expireDateTo IS NULL OR c.expireDate <= :expireDateTo) AND " +
           "(:inspectorName IS NULL OR LOWER(c.inspectorName) LIKE LOWER(CONCAT('%', :inspectorName, '%')))")
    List<Certificate> advancedSearch(
            @Param("certNumber") String certNumber,
            @Param("manufacturer") String manufacturer,
            @Param("modelName") String modelName,
            @Param("vin") String vin,
            @Param("country") String country,
            @Param("status") CertificateStatus status,
            @Param("issueDateFrom") LocalDate issueDateFrom,
            @Param("issueDateTo") LocalDate issueDateTo,
            @Param("expireDateFrom") LocalDate expireDateFrom,
            @Param("expireDateTo") LocalDate expireDateTo,
            @Param("inspectorName") String inspectorName);

    // Statistics queries
    long countByStatus(CertificateStatus status);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.expireDate > :today AND c.status = 'VALID'")
    long countValidCertificates(@Param("today") LocalDate today);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.expireDate <= :today AND c.status = 'VALID'")
    long countExpiredCertificates(@Param("today") LocalDate today);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.expireDate BETWEEN :today AND :expiringSoon AND c.status = 'VALID'")
    long countExpiringSoonCertificates(@Param("today") LocalDate today, @Param("expiringSoon") LocalDate expiringSoon);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE :userId MEMBER OF c.issuerUserIds")
    long countByIssuerUserId(@Param("userId") Long userId);

    @Query("SELECT COUNT(c) FROM Certificate c WHERE c.user.id = :userId")
    long countByUserId(@Param("userId") Long userId);

    // 현재 사용자가 발급받은 인증서 조회 (user_id 기준)
    List<Certificate> findByUserId(Long userId);

    /**
     * 사용자 ID로 인증서 조회 (issuerUserIds 함께 fetch)
     * N+1 문제 방지를 위해 LEFT JOIN FETCH 사용
     */
    @Query("SELECT DISTINCT c FROM Certificate c LEFT JOIN FETCH c.issuerUserIds WHERE c.user.id = :userId")
    List<Certificate> findByUserIdWithFetch(@Param("userId") Long userId);

    // 사용자 탈퇴 시 인증서 처리용
    @Modifying
    @Query("UPDATE Certificate c SET c.user = null WHERE c.user.id = :userId")
    void detachUserFromCertificates(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE Certificate c SET c.verifiedBy = null WHERE c.verifiedBy.id = :userId")
    void detachVerifierFromCertificates(@Param("userId") Long userId);
}
