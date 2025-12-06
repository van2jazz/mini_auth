package com.auth.mini.repository;

import com.auth.mini.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;


import java.util.Optional;
import java.util.UUID;


public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {
    Optional<ApiKey> findByApiKeyHash(String apiKeyHash);
}
