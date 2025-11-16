package com.isoplatform.api.certification.domain;

import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

/**
 * Value object for storing ~60 vehicle detail fields as JSON
 * This reduces Certificate entity complexity while maintaining all data
 */
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class VehicleDetails {
    private Dimensions dimensions;
    private Powertrain powertrain;
    private Specs specs;
    private Grading grading;
    private ImportDetails importDetails;

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Dimensions {
        private String length;          // e.g., "4,800 mm"
        private String width;           // e.g., "1,850 mm"
        private String height;          // e.g., "1,450 mm"
        private String wheelbase;       // e.g., "2,750 mm"
        private String trackFront;      // e.g., "1,600 mm"
        private String trackRear;       // e.g., "1,600 mm"
        private String curbWeight;      // e.g., "1,500 kg"
        private String gvm;             // Gross Vehicle Mass
        private String axleFront;       // e.g., "900 kg"
        private String axleRear;        // e.g., "1,100 kg"
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Powertrain {
        private String engineType;           // e.g., "L4 DOHC"
        private Integer cylinderCount;       // e.g., 4
        private String engineDisplacement;   // e.g., "1,998 cc"
        private String induction;            // e.g., "Turbo", "NA"
        private String enginePower;          // e.g., "150 kW"
        private String transmission;         // e.g., "8AT", "6MT"
        private String brakeType;            // e.g., "Disc/Disc"
        private String emissionStd;          // e.g., "Euro 6"
        private String motorPower;           // For EVs/Hybrids
        private String batteryVoltage;       // For EVs
        private String fuelEconomy;          // e.g., "12.5 km/L"
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Specs {
        private String engineNumber;    // e.g., "G4KE-123456"
        private Integer modelYear;      // e.g., 2023
        private String usecase;         // e.g., "승용" (passenger)
        private String colorCode;       // e.g., "2T"
        private String colorName;       // e.g., "Pearl White"
        private Integer seatCount;      // e.g., 5
        private Integer doorCount;      // e.g., 4
        private String odoType;         // e.g., "Digital", "Analog"
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class Grading {
        private String jaaiGrade;       // e.g., "4.5" (JAAI grading)
        private String aisScore;        // e.g., "85" (AIS score)
        private String aisDefectCode;   // Defect codes if any
        private String repairHistory;   // e.g., "No major repairs"
        private String comment;         // Inspector comments
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ImportDetails {
        private String destinationCountry;  // e.g., "Kenya"
        private String validityNote;        // e.g., "Valid for 6 months"
        private String disclaimer;          // Legal disclaimers
        private String radiationResult;     // e.g., "Pass"
    }
}
