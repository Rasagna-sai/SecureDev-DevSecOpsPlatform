package com.securedev.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.stereotype.Service;

import com.securedev.entity.SecurityFinding;
import com.securedev.repository.SecurityFindingRepository;

@Service
public class ScannerExecutionService {

    private static final Path SCAN_DIRECTORY =
            Path.of("/workspace");

    private static final Path GITLEAKS_REPORT =
            Path.of("/tmp/gitleaks-report.json");

    private static final Path TRIVY_REPORT =
            Path.of("/tmp/trivy-report.json");

    private static final Path GITLEAKS_LOG =
            Path.of("/tmp/gitleaks-scan.log");

    private static final Path TRIVY_LOG =
            Path.of("/tmp/trivy-scan.log");

    private static final long SCAN_TIMEOUT_MINUTES = 30;

    private final AtomicBoolean scanRunning = new AtomicBoolean(false);

    private final GitleaksReportParser gitleaksParser;
    private final TrivyReportParser trivyParser;
    private final SecurityFindingRepository repository;

    public ScannerExecutionService(
            GitleaksReportParser gitleaksParser,
            TrivyReportParser trivyParser,
            SecurityFindingRepository repository) {

        this.gitleaksParser = gitleaksParser;
        this.trivyParser = trivyParser;
        this.repository = repository;
    }

    public ScanResult scanRepository()
            throws IOException, InterruptedException {

        if (!scanRunning.compareAndSet(false, true)) {
            throw new IOException(
                    "A security scan is already running. Please wait.");
        }

        try {
            if (!Files.isDirectory(SCAN_DIRECTORY)) {
                throw new IOException(
                        "Repository directory is unavailable: "
                                + SCAN_DIRECTORY);
            }

            Files.deleteIfExists(GITLEAKS_REPORT);
            Files.deleteIfExists(TRIVY_REPORT);

            // Run Gitleaks.
            runScanner(
                    List.of(
                            "gitleaks",
                            "detect",
                            "--source", SCAN_DIRECTORY.toString(),
                            "--no-git",
                            "--report-format", "json",
                            "--report-path", GITLEAKS_REPORT.toString()
                    ),
                    GITLEAKS_LOG,
                    Set.of(0, 1)
            );

            // Run Trivy, excluding generated and unnecessary directories.
            runScanner(
                    List.of(
                            "trivy",
                            "fs",
                            "--scanners", "vuln",
                            "--skip-dirs", "/workspace/.git",
                            "--skip-dirs", "/workspace/frontend/node_modules",
                            "--skip-dirs", "/workspace/frontend/dist",
                            "--skip-dirs", "/workspace/backend/securedev-backend/target",
                            "--format", "json",
                            "--output", TRIVY_REPORT.toString(),
                            SCAN_DIRECTORY.toString()
                    ),
                    TRIVY_LOG,
                    Set.of(0)
            );

            if (!Files.isRegularFile(GITLEAKS_REPORT)
                    || !Files.isRegularFile(TRIVY_REPORT)) {
                throw new IOException(
                        "One or more scanner reports were not generated.");
            }

            // Parse the generated reports.
            List<SecurityFinding> gitleaksFindings =
                    gitleaksParser.parseReport(GITLEAKS_REPORT);

            List<SecurityFinding> trivyFindings =
                    trivyParser.parseReport(TRIVY_REPORT);

            // Save new findings without duplicating existing records.
            List<SecurityFinding> allFindings = new ArrayList<>();
            allFindings.addAll(gitleaksFindings);
            allFindings.addAll(trivyFindings);

            int inserted = saveNewFindings(allFindings);

            return new ScanResult(
                    gitleaksFindings.size(),
                    trivyFindings.size(),
                    inserted,
                    allFindings.size() - inserted
            );

        } finally {
            scanRunning.set(false);
        }
    }

    private void runScanner(
            List<String> command,
            Path logFile,
            Set<Integer> acceptedExitCodes)
            throws IOException, InterruptedException {

        ProcessBuilder processBuilder =
                new ProcessBuilder(command);

        processBuilder.redirectErrorStream(true);
        processBuilder.redirectOutput(logFile.toFile());

        Process process = processBuilder.start();

        boolean completed = process.waitFor(
                SCAN_TIMEOUT_MINUTES,
                TimeUnit.MINUTES
        );

        if (!completed) {
            process.destroyForcibly();
            process.waitFor();

            throw new IOException(
                    "Scanner timed out. Check log: " + logFile);
        }

        int exitCode = process.exitValue();

        if (!acceptedExitCodes.contains(exitCode)) {
            throw new IOException(
                    "Scanner failed with exit code "
                            + exitCode
                            + ". Check log: "
                            + logFile);
        }
    }

    private int saveNewFindings(
            List<SecurityFinding> findings) {

        List<SecurityFinding> newFindings =
                new ArrayList<>();

        Set<String> processed = new HashSet<>();

        for (SecurityFinding finding : findings) {

            String key = finding.getSourceTool()
                    + "|" + finding.getTitle()
                    + "|" + finding.getDescription();

            if (!processed.add(key)) {
                continue;
            }

            boolean exists =
                    repository.existsBySourceToolAndTitleAndDescription(
                            finding.getSourceTool(),
                            finding.getTitle(),
                            finding.getDescription()
                    );

            if (!exists) {
                newFindings.add(finding);
            }
        }

        if (!newFindings.isEmpty()) {
            repository.saveAll(newFindings);
        }

        return newFindings.size();
    }

    public record ScanResult(
            int gitleaksFindings,
            int trivyFindings,
            int insertedFindings,
            int duplicateFindings) {
    }
}