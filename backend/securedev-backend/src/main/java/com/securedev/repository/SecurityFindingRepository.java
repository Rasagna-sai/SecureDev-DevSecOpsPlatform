package com.securedev.repository;

import com.securedev.entity.SecurityFinding;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SecurityFindingRepository
        extends JpaRepository<SecurityFinding, Long> {
}