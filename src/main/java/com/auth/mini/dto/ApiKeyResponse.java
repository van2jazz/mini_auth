package com.auth.mini.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
@AllArgsConstructor
public class ApiKeyResponse {
    private String apiKey;
    private String serviceName;
    private long ttlSeconds;      // add this
    private boolean active;
}

