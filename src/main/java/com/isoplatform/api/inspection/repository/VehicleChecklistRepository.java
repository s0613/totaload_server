package com.isoplatform.api.inspection.repository;

import com.isoplatform.api.inspection.VehicleChecklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VehicleChecklistRepository extends JpaRepository<VehicleChecklist, Long> {
    Optional<VehicleChecklist> findByVin(String vin);
}
