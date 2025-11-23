package com.isoplatform.api.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.LocalDate;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JacksonConfigTest {

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void localDate_shouldSerializeAsIsoString() throws Exception {
        LocalDate date = LocalDate.of(2024, 11, 23);

        String json = objectMapper.writeValueAsString(date);

        assertThat(json).isEqualTo("\"2024-11-23\"");
    }

    @Test
    void localDateTime_shouldSerializeAsIsoString() throws Exception {
        LocalDateTime dateTime = LocalDateTime.of(2024, 11, 23, 10, 30, 0);

        String json = objectMapper.writeValueAsString(dateTime);

        assertThat(json).isEqualTo("\"2024-11-23T10:30:00\"");
    }

    record TestDto(LocalDate date, LocalDateTime dateTime) {}

    @Test
    void dto_shouldSerializeDatesAsIsoStrings() throws Exception {
        TestDto dto = new TestDto(
                LocalDate.of(2024, 11, 23),
                LocalDateTime.of(2024, 11, 23, 10, 30, 0)
        );

        String json = objectMapper.writeValueAsString(dto);

        assertThat(json).contains("\"date\":\"2024-11-23\"");
        assertThat(json).contains("\"dateTime\":\"2024-11-23T10:30:00\"");
    }
}
