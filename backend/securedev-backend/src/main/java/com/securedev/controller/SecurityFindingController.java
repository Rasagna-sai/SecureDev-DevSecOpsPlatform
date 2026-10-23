package com.securedev.controller;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.securedev.entity.SecurityFinding;
import com.securedev.repository.SecurityFindingRepository;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/findings")
public class SecurityFindingController {

    private final SecurityFindingRepository repository;

    public SecurityFindingController(SecurityFindingRepository repository) {
        this.repository = repository;
    }

    @PostMapping
    public SecurityFinding createFinding(@Valid @RequestBody SecurityFinding finding) {
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
                    "Finding not found: " + id
            ));
}
}