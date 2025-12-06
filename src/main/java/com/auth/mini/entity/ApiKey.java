package com.auth.mini.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.UUID;


@Entity
@Table(name = "api_keys")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ApiKey {



    @Id
    @GeneratedValue
    private UUID id;


    @Column(nullable = false)
    private String serviceName;


    @Column(nullable = false, unique = true)
    private String apiKeyHash; // bcrypt or other KDF of the raw key


    private boolean revoked;


    private Instant createdAt;


    private Instant expiresAt;


    private String notes;

    @JsonIgnore
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("SERVICE_ADMIN"));
    }
}
