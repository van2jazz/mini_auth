package com.auth.mini.security;

import com.auth.mini.config.JwtUtil;
import com.auth.mini.entity.ApiKey;
import com.auth.mini.service.ApiKeyService;
import com.auth.mini.service.UserService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class CombinedAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final UserService userService;
    private final ApiKeyService apiKeyService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        // Already authenticated? Skip.
        if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }

        // 1️⃣ Attempt JWT authentication
        boolean jwtAuthenticated = tryJwtAuth(request);

        // If JWT worked → skip API key
        if (!jwtAuthenticated) {
            // 2️⃣ Attempt API key authentication
            tryApiKeyAuth(request);
        }

        filterChain.doFilter(request, response);
    }

    private boolean tryJwtAuth(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return false;
        }

        String token = header.substring(7);

        try {
            Jws<Claims> parsed = jwtUtil.validateAndParse(token);
            Claims claims = parsed.getBody();

            String userId = claims.getSubject();
            if (userId == null) return false;

            var userDetails = userService.loadUserById(userId);

            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

            auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(auth);
            return true;

        } catch (JwtException e) {
            return false;
        }
    }

    private boolean tryApiKeyAuth(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-KEY");

        if (apiKey == null || apiKey.isBlank()) {
            return false;
        }

        ApiKey key = apiKeyService.validateRawKey(apiKey);
        if (key == null) {
            return false;
        }

        // API keys represent machines/services → assign authority
        var auth = new UsernamePasswordAuthenticationToken(
                key,
                null,
                key.getAuthorities()  // from your ApiKey entity
        );

        auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(auth);

        return true;
    }
}
