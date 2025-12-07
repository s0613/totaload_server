package com.isoplatform.api.accident.repository;

import com.isoplatform.api.accident.AccidentHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface AccidentHistoryRepository extends JpaRepository<AccidentHistory, Long> {

    List<AccidentHistory> findByVinOrderByAccidentDateDesc(String vin);

    List<AccidentHistory> findByRegisteredBy(Long userId);

    int countByVin(String vin);
}
