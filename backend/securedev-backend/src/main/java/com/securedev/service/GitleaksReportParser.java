package com.securedev.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.entity.SecurityFinding;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class GitleaksReportParser {

    private final ObjectMapper objectMapper;

    public GitleaksReportParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<SecurityFinding> parseReport(Path reportPath)
            throws IOException {

        List<Map<String, Object>> report = objectMapper.readValue(
                reportPath.toFile(),
                new TypeReference<List<Map<String, Object>>>() {}
        );

        List<SecurityFinding> findings = new ArrayList<>();

        for (Map<String, Object> item : report) {
            SecurityFinding finding = new SecurityFinding();

            String ruleId = String.valueOf(
                    item.getOrDefault("RuleID", "unknown-rule"));

            String file = String.valueOf(
                    item.getOrDefault("File", "unknown file"));

            String severity = mapSeverity(ruleId);

            finding.setTitle("Potential secret detected: " + ruleId);
            finding.setDescription(
                    "Gitleaks detected a potential secret in file: " + file
                            + ". Review the finding and rotate the credential "
                            + "if it is confirmed exposed.");
            finding.setSeverity(severity);
            finding.setSourceTool("Gitleaks");

            findings.add(finding);
        }

        return findings;
    }

    private String mapSeverity(String ruleId) {
        String rule = ruleId.toLowerCase();

        if (rule.contains("private-key")) {
            return "CRITICAL";
        }

        if (rule.contains("aws") || rule.contains("api-key")
        || rule.contains("token") || rule.contains("password")
        || rule.contains("secret")) {
        return "HIGH";
}

        return "MEDIUM";
    }
}

