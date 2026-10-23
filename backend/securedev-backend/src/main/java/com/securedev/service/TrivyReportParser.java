
package com.securedev.service;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.entity.SecurityFinding;

@Service
public class TrivyReportParser {

    private final ObjectMapper objectMapper;

    public TrivyReportParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<SecurityFinding> parseReport(Path reportPath)
            throws IOException {
        JsonNode root = objectMapper.readTree(reportPath.toFile());
        return parseReportNode(root);
    }

    public List<SecurityFinding> parseReportFromJson(String reportJson)
            throws IOException {
        JsonNode root = objectMapper.readTree(reportJson);
        return parseReportNode(root);
    }

    private List<SecurityFinding> parseReportNode(JsonNode root)
            throws IOException {

        if (root == null || !root.isObject()) {
            throw new IOException("Invalid Trivy report: expected a JSON object");
        }

        JsonNode results = root.path("Results");
        if (!results.isArray()) {
            throw new IOException(
                    "Invalid Trivy report: missing Results array");
        }

        String imageName = root.path("ArtifactName").asText("unknown image");
        List<SecurityFinding> findings = new ArrayList<>();

        for (JsonNode result : results) {
            JsonNode vulnerabilities = result.path("Vulnerabilities");

            if (!vulnerabilities.isArray()) {
                continue;
            }

            String target = result.path("Target").asText("unknown target");

            for (JsonNode vulnerability : vulnerabilities) {
                String vulnerabilityId =
                        vulnerability.path("VulnerabilityID")
                                .asText("UNKNOWN-VULNERABILITY");

                String packageName =
                        vulnerability.path("PkgName").asText("unknown package");

                String installedVersion =
                        vulnerability.path("InstalledVersion").asText("unknown");

                String fixedVersion =
                        vulnerability.path("FixedVersion").asText("");

                String severity = mapSeverity(
                        vulnerability.path("Severity").asText("UNKNOWN"));

                SecurityFinding finding = new SecurityFinding();

                finding.setTitle(
                        limit("Trivy: " + vulnerabilityId + " in " + packageName,
                                200));

                String description =
                        "Container image: " + imageName
                        + "; target: " + target
                        + "; package: " + packageName
                        + "; installed version: " + installedVersion
                        + (fixedVersion.isBlank()
                            ? "; no fixed version reported."
                            : "; fixed version: " + fixedVersion + ".");

                finding.setDescription(limit(description, 2000));
                finding.setSeverity(severity);
                finding.setSourceTool("Trivy");

                findings.add(finding);
            }
        }

        return findings;
    }

    private String mapSeverity(String severity) {
        return switch (severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "CRITICAL";
            case "HIGH" -> "HIGH";
            case "MEDIUM" -> "MEDIUM";
            case "LOW" -> "LOW";
            default -> "LOW";
        };
    }

    private String limit(String value, int maxLength) {
        return value.length() <= maxLength
                ? value
                : value.substring(0, maxLength);
    }
}
