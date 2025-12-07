package com.isoplatform.api.certification.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.isoplatform.api.certification.domain.VehicleDetails;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * JPA converter for VehicleDetails <-> JSON string
 * Automatically converts VehicleDetails object to JSON when saving to DB
 * and JSON string back to VehicleDetails when loading from DB
 */
@Converter
public class VehicleDetailsConverter implements AttributeConverter<VehicleDetails, String> {

    private static final ObjectMapper mapper = new ObjectMapper();

    @Override
    public String convertToDatabaseColumn(VehicleDetails details) {
        if (details == null) {
            return null;
        }
        try {
            return mapper.writeValueAsString(details);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to convert VehicleDetails to JSON", e);
        }
    }

    @Override
    public VehicleDetails convertToEntityAttribute(String dbData) {
        if (dbData == null || dbData.isBlank()) {
            return null;
        }
        try {
            return mapper.readValue(dbData, VehicleDetails.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to convert JSON to VehicleDetails", e);
        }
    }
}
