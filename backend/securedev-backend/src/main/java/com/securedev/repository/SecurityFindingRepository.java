
package com.securedev.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.securedev.entity.SecurityFinding;

public interface SecurityFindingRepository
        extends JpaRepository<SecurityFinding, Long> {

    boolean existsBySourceToolAndTitleAndDescription(
            String sourceTool,
            String title,
            String description
    );

    long countBySourceTool(String sourceTool);

    List<SecurityFinding> findAllByOrderByDetectedAtDesc();
}
