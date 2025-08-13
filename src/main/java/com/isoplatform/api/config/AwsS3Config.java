package com.isoplatform.api.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.S3Client;

@Configuration
public class AwsS3Config {

    @Value("${cloud.aws.region.static}")
    private String region;

    @Value("${cloud.aws.credentials.access-key:}")
    private String accessKey;

    @Value("${cloud.aws.credentials.secret-key:}")
    private String secretKey;

    @Bean
    public S3Client s3Client() {
        var builder = S3Client.builder()
                .region(Region.of(region))
                .serviceConfiguration(S3Configuration.builder()
                        .pathStyleAccessEnabled(false)
                        .build());

        // yml에 키가 있으면 그걸 사용, 없으면 기본 체인
        if (accessKey != null && !accessKey.isBlank()
                && secretKey != null && !secretKey.isBlank()) {
            var creds = software.amazon.awssdk.auth.credentials.AwsBasicCredentials.create(accessKey, secretKey);
            builder = builder.credentialsProvider(
                    software.amazon.awssdk.auth.credentials.StaticCredentialsProvider.create(creds)
            );
        } else {
            builder = builder.credentialsProvider(software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider.create());
        }

        return builder.build();
    }
}

