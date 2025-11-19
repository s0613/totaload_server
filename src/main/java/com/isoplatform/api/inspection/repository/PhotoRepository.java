package com.isoplatform.api.inspection.repository;

import com.isoplatform.api.inspection.Photo;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PhotoRepository extends JpaRepository<Photo, Long> {
    List<Photo> findByVin(String vin);
    List<Photo> findByChecklistId(Long checklistId);
    List<Photo> findByVinAndCategory(String vin, String category);
}
