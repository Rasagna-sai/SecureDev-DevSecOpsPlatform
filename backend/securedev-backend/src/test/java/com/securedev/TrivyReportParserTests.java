
package com.securedev;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import org.junit.jupiter.api.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.entity.SecurityFinding;
import com.securedev.service.TrivyReportParser;

class TrivyReportParserTests {

    private final TrivyReportParser parser =
            new TrivyReportParser(new ObjectMapper());

    @Test
    void validReportConvertsVulnerabilityToFinding() throws Exception {
        String report = """
            {
              "ArtifactName": "alpine:3.20",
              "Results": [
                {
                  "Target": "alpine:3.20",
                  "Vulnerabilities": [
                    {
                      "VulnerabilityID": "CVE-TEST-123",
                      "PkgName": "test-package",
                      "InstalledVersion": "1.0",
                      "FixedVersion": "1.1",
                      "Severity": "HIGH"
                    }
                  ]
                }
              ]
            }
            """;

        List<SecurityFinding> findings =
                parser.parseReportFromJson(report);

        assertEquals(1, findings.size());
        assertEquals("Trivy: CVE-TEST-123 in test-package",
                findings.get(0).getTitle());
        assertEquals("HIGH", findings.get(0).getSeverity());
        assertEquals("Trivy", findings.get(0).getSourceTool());
        assertEquals(true,
                findings.get(0).getDescription().contains("alpine:3.20"));
    }

    @Test
    void emptyResultsReturnsNoFindings() throws Exception {
        String report = """
            {
              "ArtifactName": "alpine:3.20",
              "Results": []
            }
            """;

        List<SecurityFinding> findings =
                parser.parseReportFromJson(report);

        assertEquals(0, findings.size());
    }

    @Test
    void missingResultsArrayThrowsIOException() {
        String report = """
            {
              "ArtifactName": "alpine:3.20"
            }
            """;

        assertThrows(IOException.class,
                () -> parser.parseReportFromJson(report));
    }

    @Test
    void malformedJsonThrowsIOException() {
        String report = "{ invalid json";

        assertThrows(IOException.class,
                () -> parser.parseReportFromJson(report));
    }

    @Test
void realTrivyReportFixtureConvertsVulnerabilityCorrectly()
        throws Exception {

    String report = java.nio.file.Files.readString(
            java.nio.file.Path.of(
                    "src/test/resources/reports/trivy-sample.json"));

    List<SecurityFinding> findings =
            parser.parseReportFromJson(report);

    assertEquals(1, findings.size());

    SecurityFinding finding = findings.get(0);

    assertEquals(
            "Trivy: CVE-2026-89407 in com.fasterxml.jackson.core:jackson-core",
            finding.getTitle());

    assertEquals("HIGH", finding.getSeverity());
    assertEquals("Trivy", finding.getSourceTool());

    org.junit.jupiter.api.Assertions.assertTrue(
            finding.getDescription().contains("2.21.5"));

    org.junit.jupiter.api.Assertions.assertTrue(
            finding.getDescription().contains("2.18.11"));
}
}
