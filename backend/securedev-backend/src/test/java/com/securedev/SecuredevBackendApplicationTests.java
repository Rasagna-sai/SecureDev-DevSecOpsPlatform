package com.securedev;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.securedev.controller.SecurityFindingController;
import com.securedev.entity.SecurityFinding;
import com.securedev.exception.GlobalExceptionHandler;
import com.securedev.repository.SecurityFindingRepository;
import com.securedev.service.GitleaksReportParser;
import com.securedev.service.RiskPrioritizationService;
import com.securedev.service.TrivyReportParser;

@WebMvcTest(SecurityFindingController.class)
@Import(GlobalExceptionHandler.class)
class SecuredevBackendApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private SecurityFindingRepository repository;

	@MockitoBean
	private GitleaksReportParser gitleaksReportParser;

    @MockitoBean
private TrivyReportParser trivyReportParser;

	@MockitoBean
	private ObjectMapper objectMapper;

    @MockitoBean
private RiskPrioritizationService riskPrioritizationService;

    @Test
    void createFindingReturnsCreatedFinding() throws Exception {
        SecurityFinding saved = new SecurityFinding();
        saved.setTitle("Hardcoded API key");
        saved.setDescription("Secret found in source code");
        saved.setSeverity("HIGH");
        saved.setSourceTool("Gitleaks");

        when(repository.save(any(SecurityFinding.class))).thenReturn(saved);

        mockMvc.perform(post("/api/findings")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "title": "Hardcoded API key",
                      "description": "Secret found in source code",
                      "severity": "HIGH",
                      "sourceTool": "Gitleaks"
                    }
                    """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Hardcoded API key"))
                .andExpect(jsonPath("$.severity").value("HIGH"));
    }

    @Test
    void listFindingsReturnsFindings() throws Exception {
        SecurityFinding finding = new SecurityFinding();
        finding.setTitle("Vulnerable container");
        finding.setSeverity("CRITICAL");
        finding.setSourceTool("Trivy");

        when(repository.findAll()).thenReturn(List.of(finding));

        mockMvc.perform(get("/api/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].title").value("Vulnerable container"))
                .andExpect(jsonPath("$[0].severity").value("CRITICAL"));
    }

    @Test
    void getMissingFindingReturnsNotFound() throws Exception {
        when(repository.findById(99999L)).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/findings/99999"))
                .andExpect(status().isNotFound());
    }

    @Test
    void invalidFindingReturnsBadRequest() throws Exception {
        mockMvc.perform(post("/api/findings")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                    {
                      "title": "",
                      "severity": "URGENT",
                      "sourceTool": ""
                    }
                    """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.title").exists())
                .andExpect(jsonPath("$.severity").exists())
                .andExpect(jsonPath("$.sourceTool").exists());
    }
}