package com.auth.mini.controller;

import com.auth.mini.dto.ApiKeyResponse;
import com.auth.mini.service.ApiKeyService;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@Builder
@RestController
@RequestMapping("/keys")
@RequiredArgsConstructor
public class ApiKeyController {

    private final ApiKeyService apiKeyService;

    @PostMapping("/create")
    public ResponseEntity<ApiKeyResponse> createKey(
            @RequestParam(required = false) String serviceName,
            @RequestParam(defaultValue = "2592000") long ttlSeconds  // 30 days
    ) {
        String rawKey = apiKeyService.createKey(serviceName, ttlSeconds);

        ApiKeyResponse keyResponse = ApiKeyResponse.builder()
                .serviceName(serviceName)
                .apiKey(rawKey)
                .ttlSeconds(ttlSeconds)
                .build();

        return ResponseEntity.ok(keyResponse);
    }


    @PostMapping("/revoke/{keyId}")
    public ResponseEntity<?> revokeKey(@PathVariable UUID keyId) {
        apiKeyService.revoke(keyId);
        return ResponseEntity.ok("API Key revoked successfully");
    }
}

