
package com.securedev;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.entity.SecurityFinding;
import com.securedev.service.GitleaksReportParser;

class GitleaksReportParserTests {

    private final GitleaksReportParser parser =
            new GitleaksReportParser(new ObjectMapper());

    @TempDir
    Path tempDir;

    @Test
    void emptyGitleaksReportReturnsNoFindings() throws Exception {
        Path report = tempDir.resolve("empty-report.json");
        Files.writeString(report, "[]");

        List<SecurityFinding> findings = parser.parseReport(report);

        assertTrue(findings.isEmpty());
    }

    @Test
    void gitleaksReportConvertsEntryToSecurityFinding() throws Exception {
        Path report = tempDir.resolve("sample-report.json");

        Files.writeString(report, """
            [
              {
                "RuleID": "generic-api-key",
                "File": "src/example.txt",
                "Secret": "REDACTED_TEST_VALUE"
              }
            ]
            """);

        List<SecurityFinding> findings = parser.parseReport(report);

        assertEquals(1, findings.size());
        assertEquals(
                "Potential secret detected: generic-api-key",
                findings.get(0).getTitle());
        assertEquals("HIGH", findings.get(0).getSeverity());
        assertEquals("Gitleaks", findings.get(0).getSourceTool());
        assertFalse(
                findings.get(0).getDescription()
                        .contains("REDACTED_TEST_VALUE"));
    }
}
