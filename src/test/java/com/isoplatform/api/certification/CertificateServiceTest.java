package com.isoplatform.api.certification;

import com.isoplatform.api.auth.Role;
import com.isoplatform.api.auth.User;
import com.isoplatform.api.auth.repository.UserRepository;
import com.isoplatform.api.certification.repository.CertificateRepository;
import com.isoplatform.api.certification.request.CertificateRequest;
import com.isoplatform.api.certification.response.CertificateResponse;
import com.isoplatform.api.certification.service.CertificateService;
import com.isoplatform.api.util.Gemini;
import com.isoplatform.api.util.PDFParser;
import com.isoplatform.api.util.PdfImageConverter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.io.TempDir;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@ActiveProfiles("test")
@Transactional
public class CertificateServiceTest {

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EntityManager entityManager;

    @MockBean
    private Gemini gemini;

    @MockBean
    private PDFParser pdfParser;

    @MockBean
    private PdfImageConverter pdfImageConverter;

    @TempDir
    Path tempDir;

    private User testUser;
    private File testPdfFile;

    @BeforeEach
    public void setUp() throws Exception {
        // 테스트 사용자 생성 및 DB에 저장
        testUser = User.builder()
                .email("test@example.com")
                .password("password")
                .name("테스트 사용자")
                .role(Role.USER)
                .build();

        // 사용자 저장
        testUser = userRepository.save(testUser);
        entityManager.flush();

        // 실제 테스트 PDF 파일 생성
        testPdfFile = tempDir.resolve("test-certificate.pdf").toFile();
        Files.write(testPdfFile.toPath(), "Test PDF Content".getBytes());

        // PDFParser 모킹 - 실제 파일 경로 반환
        when(pdfParser.createCertificatePdf(any()))
                .thenReturn(testPdfFile.getAbsolutePath());

        // SecurityContext 설정
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        "test@example.com",
                        "password",
                        Collections.emptyList()
                );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Test
    public void testCreateAndGenerate() {
        // Given
        CertificateRequest request = new CertificateRequest();
        request.setVin("KMHD35LE5HU123456");
        request.setManufacturer("현대자동차");
        request.setModelName("아반떼");
        request.setManufactureYear(2020);
        request.setFirstRegisterDate(LocalDate.of(2020, 3, 15));
        request.setMileage(50000);
        request.setInspectDate(LocalDate.now());
        request.setInspectorCode("INS001");
        request.setInspectorName("김검사");

        // When
        CertificateResponse response = certificateService.createAndGenerate(request);

        // Then
        assertNotNull(response);
        assertNotNull(response.getCertNumber());
        assertEquals(request.getVin(), response.getVin());
        assertEquals(request.getManufacturer(), response.getManufacturer());
        assertEquals(request.getModelName(), response.getModelName());

        // 데이터베이스에 저장되었는지 확인
        assertTrue(certificateRepository.existsByVin(request.getVin()));
    }

    @Test
    public void testDuplicateVinReturnsExisting() {
        // Given
        CertificateRequest request = new CertificateRequest();
        request.setVin("KMHD35LE5HU123456");
        request.setManufacturer("현대자동차");
        request.setModelName("아반떼");
        request.setInspectDate(LocalDate.now());
        request.setInspectorCode("INS001");
        request.setInspectorName("김검사");

        // 첫 번째 인증서 생성
        CertificateResponse first = certificateService.createAndGenerate(request);

        // When - 같은 VIN으로 다시 요청
        CertificateResponse second = certificateService.createAndGenerate(request);

        // Then - 기존 인증서를 반환해야 함
        assertNotNull(second);
        assertEquals(first.getCertNumber(), second.getCertNumber());
        assertEquals(first.getVin(), second.getVin());
    }
}
