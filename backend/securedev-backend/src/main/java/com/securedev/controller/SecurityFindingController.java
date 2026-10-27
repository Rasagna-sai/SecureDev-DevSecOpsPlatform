
package com.securedev.controller;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.entity.SecurityFinding;
import com.securedev.repository.SecurityFindingRepository;
import com.securedev.service.GitleaksReportParser;
import com.securedev.service.RiskPrioritizationService;
import com.securedev.service.TrivyReportParser;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/findings")
@CrossOrigin(origins = "http://localhost:5173")
public class SecurityFindingController {

    private final SecurityFindingRepository repository;
    private final GitleaksReportParser gitleaksReportParser;
    private final ObjectMapper objectMapper;
    private final RiskPrioritizationService riskPrioritizationService;
    private final TrivyReportParser trivyReportParser;

    public SecurityFindingController(
        SecurityFindingRepository repository,
        GitleaksReportParser gitleaksReportParser,
        TrivyReportParser trivyReportParser,
        RiskPrioritizationService riskPrioritizationService,
        ObjectMapper objectMapper) {

    this.repository = repository;
    this.gitleaksReportParser = gitleaksReportParser;
    this.trivyReportParser = trivyReportParser;
    this.riskPrioritizationService = riskPrioritizationService;
    this.objectMapper = objectMapper;
}

    @PostMapping
    public SecurityFinding createFinding(
            @Valid @RequestBody SecurityFinding finding) {
        return repository.save(finding);
    }

    @GetMapping
    public List<SecurityFinding> getAllFindings() {
        return repository.findAll();
    }

    @GetMapping("/{id}")
    public SecurityFinding getFindingById(@PathVariable Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Finding not found: " + id));
    }
    @GetMapping("/prioritized")
    public List<SecurityFinding> getPrioritizedFindings() {
        return riskPrioritizationService.getPrioritizedFindings();
}

    @PostMapping("/import/trivy")
public List<SecurityFinding> importTrivyReport(
        @RequestBody String reportJson) {
    try {
        List<SecurityFinding> findings =
                trivyReportParser.parseReportFromJson(reportJson);

        List<SecurityFinding> newFindings = new java.util.ArrayList<>();

        for (SecurityFinding finding : findings) {
            boolean exists = repository.existsBySourceToolAndTitleAndDescription(
                    finding.getSourceTool(),
                    finding.getTitle(),
                    finding.getDescription()
            );

            if (!exists) {
                newFindings.add(finding);
            }
        }

        return repository.saveAll(newFindings);
    } catch (IOException ex) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Invalid Trivy report JSON",
                ex
        );
    }
}
    
@PostMapping("/import/gitleaks")
public List<SecurityFinding> importGitleaksReport(
        @RequestBody String reportJson) {
    try {
        List<SecurityFinding> findings = gitleaksReportParser
                .parseReportFromJson(reportJson);

        List<SecurityFinding> newFindings = new java.util.ArrayList<>();

        for (SecurityFinding finding : findings) {
            boolean exists = repository
                    .existsBySourceToolAndTitleAndDescription(
                            finding.getSourceTool(),
                            finding.getTitle(),
                            finding.getDescription()
                    );

            if (!exists) {
                newFindings.add(finding);
            }
        }

        return repository.saveAll(newFindings);
    } catch (IOException ex) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Invalid Gitleaks report JSON",
                ex);
    }
}
    @PatchMapping("/{id}/status")
public SecurityFinding updateFindingStatus(
        @PathVariable Long id,
        @RequestBody Map<String, String> request) {

    String status = request.get("status");

    if (status == null ||
            (!status.equals("OPEN") && !status.equals("RESOLVED"))) {
        throw new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Status must be OPEN or RESOLVED");
    }


    SecurityFinding finding = repository.findById(id)
            .orElseThrow(() -> new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    "Finding not found: " + id));

    finding.setStatus(status);

    return repository.save(finding);
}

}
