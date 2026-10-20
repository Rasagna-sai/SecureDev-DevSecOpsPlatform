package com.securedev.controller;

import com.securedev.entity.SecurityFinding;
import com.securedev.repository.SecurityFindingRepository;
import java.util.List;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/findings")
public class SecurityFindingController {

    private final SecurityFindingRepository repository;

    public SecurityFindingController(SecurityFindingRepository repository) {
        this.repository = repository;
    }

    @PostMapping
    public SecurityFinding createFinding(@RequestBody SecurityFinding finding) {
        return repository.save(finding);
    }

    @GetMapping
    public List<SecurityFinding> getAllFindings() {
        return repository.findAll();
    }

    @GetMapping("/{id}")
    public SecurityFinding getFindingById(@PathVariable Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new RuntimeException("Finding not found: " + id));
    }
}