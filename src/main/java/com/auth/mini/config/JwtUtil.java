package com.auth.mini.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;


import java.security.Key;
import java.util.Date;
import java.util.Map;


@Component
public class JwtUtil {

    private final Key key;
    private final long jwtExpirationMs;

    public JwtUtil(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.exp-ms}") long jwtExpirationMs
    ) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateToken(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(now + jwtExpirationMs))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> validateAndParse(String token) throws JwtException {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            String subject = validateAndParse(token).getBody().getSubject();
            return subject.equals(userDetails.getUsername());
        } catch (Exception e) {
            return false;
        }
    }
}

