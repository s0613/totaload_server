package com.isoplatform.api.util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
@Service
@RequiredArgsConstructor
public class S3Service {

    @Value("${cloud.aws.s3.bucket:totaload}")
    private String bucket;

    @Value("${cloud.aws.cloudfront.distribution-domain:}")
    private String cloudFrontDomain;

    private final S3Client s3Client;

    /**
     * 파일을 S3에 업로드하고 CloudFront URL을 반환합니다.
     *
     * @param localFilePath 로컬 파일 경로
     * @param s3Key S3 키 (저장될 경로)
     * @return S3UploadResult 업로드 결과
     */
    public S3UploadResult uploadFile(String localFilePath, String s3Key) {
        try {
            Path filePath = Paths.get(localFilePath);
            File file = filePath.toFile();

            if (!file.exists()) {
                throw new IllegalArgumentException("파일이 존재하지 않습니다: " + localFilePath);
            }

            PutObjectRequest putObjectRequest = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(s3Key)
                    .contentType(getContentType(localFilePath))
                    .build();

            s3Client.putObject(putObjectRequest, RequestBody.fromFile(filePath));

            String cloudFrontUrl = generateCloudFrontUrl(s3Key);

            log.info("S3 업로드 완료 - bucket: {}, key: {}, url: {}", bucket, s3Key, cloudFrontUrl);

            return S3UploadResult.builder()
                    .s3Key(s3Key)
                    .cloudFrontUrl(cloudFrontUrl)
                    .build();

        } catch (Exception e) {
            log.error("S3 업로드 중 오류 - file: {}, key: {}", localFilePath, s3Key, e);
            throw new RuntimeException("S3 업로드 실패: " + e.getMessage(), e);
        }
    }

    public void deleteLocalFile(String localFilePath) {
        try {
            Path path = Paths.get(localFilePath);
            File file = path.toFile();

            if (file.exists() && file.delete()) {
                log.info("로컬 파일 삭제 완료: {}", localFilePath);
            } else {
                log.warn("로컬 파일 삭제 실패 또는 파일 없음: {}", localFilePath);
            }
        } catch (Exception e) {
            log.error("로컬 파일 삭제 중 오류: {}", localFilePath, e);
        }
    }

    private String generateCloudFrontUrl(String s3Key) {
        if (cloudFrontDomain == null || cloudFrontDomain.isBlank()) {
            // CloudFront 미설정 시 S3 가상호스티드 스타일 URL로 대체
            return "https://" + bucket + ".s3.amazonaws.com/" + s3Key;
        }
        return "https://" + cloudFrontDomain + "/" + s3Key;
    }

    private String getContentType(String filePath) {
        String fileName = filePath.toLowerCase();
        if (fileName.endsWith(".pdf")) return "application/pdf";
        if (fileName.endsWith(".jpg") || fileName.endsWith(".jpeg")) return "image/jpeg";
        if (fileName.endsWith(".png")) return "image/png";
        if (fileName.endsWith(".gif")) return "image/gif";
        return "application/octet-stream";
    }
}
