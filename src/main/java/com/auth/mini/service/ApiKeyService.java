package com.auth.mini.service;


import com.auth.mini.entity.ApiKey;
import com.auth.mini.repository.ApiKeyRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;


@Service
public class ApiKeyService {
    private final ApiKeyRepository apiKeyRepository;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    private final SecureRandom secureRandom = new SecureRandom();


    public ApiKeyService(ApiKeyRepository apiKeyRepository) {
        this.apiKeyRepository = apiKeyRepository;
    }


    // returns the rawKey (once) and saves only hashed
    public String createKey(String serviceName, long ttlSeconds) {
// generate raw key: 32 bytes base64
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        String raw = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);


        String hashed = encoder.encode(raw);


        ApiKey apiKey = ApiKey.builder()
                .serviceName(serviceName)
                .apiKeyHash(hashed)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(ttlSeconds))
                .revoked(false)
                .build();


        apiKeyRepository.save(apiKey);


// Return raw to caller ONE TIME
        return raw;
    }


    public ApiKey validateRawKey(String rawKey) {
// Since we store hashed keys, we need to check with each stored hash.
// For scale: store additional fingerprint (SHA-256 of raw) to lookup quickly; for small scale, iterate.
        for (ApiKey k : apiKeyRepository.findAll()) {
            if (!k.isRevoked() && k.getExpiresAt() != null && k.getExpiresAt().isBefore(Instant.now())) continue;
            if (encoder.matches(rawKey, k.getApiKeyHash())) {
                return k;
            }
        }
        return null;
    }


    public void revoke(UUID id) {
        apiKeyRepository.findById(id).ifPresent(k -> {
            k.setRevoked(true);
            apiKeyRepository.save(k);
        });
    }
}
