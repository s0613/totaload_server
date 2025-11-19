package com.isoplatform.api.inspection.repository;

import com.isoplatform.api.inspection.ChecklistItem;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ChecklistItemRepository extends JpaRepository<ChecklistItem, Long> {
}
