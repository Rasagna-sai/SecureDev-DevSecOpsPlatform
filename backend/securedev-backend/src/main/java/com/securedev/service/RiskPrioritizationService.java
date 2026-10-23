
package com.securedev.service;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.securedev.entity.SecurityFinding;
import com.securedev.repository.SecurityFindingRepository;

@Service
public class RiskPrioritizationService {

    private final SecurityFindingRepository repository;

    private static final Map<String, Integer> SEVERITY_RANK =
            Map.of(
                    "CRITICAL", 1,
                    "HIGH", 2,
                    "MEDIUM", 3,
                    "LOW", 4
            );

    public RiskPrioritizationService(
            SecurityFindingRepository repository) {
        this.repository = repository;
    }

    public List<SecurityFinding> getPrioritizedFindings() {
        return repository.findAllByOrderByDetectedAtDesc()
                .stream()
                .sorted(Comparator.comparingInt(
                        finding -> SEVERITY_RANK.getOrDefault(
                                finding.getSeverity(), 5)))
                .toList();
    }
}
