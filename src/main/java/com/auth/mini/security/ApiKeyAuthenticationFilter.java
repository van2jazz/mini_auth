package com.auth.mini.security;


import com.auth.mini.entity.ApiKey;
import com.auth.mini.service.ApiKeyService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private final ApiKeyService apiKeyService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {

        String apiKey = request.getHeader("x-api-key");

        if (apiKey != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            var serviceDetails = apiKeyService.validateRawKey(apiKey);

            if (serviceDetails != null) {
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(
                                serviceDetails,
                                null,
                                List.of(new SimpleGrantedAuthority("ROLE_SERVICE"))
                        );

                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }

        filterChain.doFilter(request, response);
    }

    public boolean attemptAuthentication(HttpServletRequest request) {
        try {
            String apiKey = request.getHeader("X-API-KEY");

            if (apiKey == null) return false;

            ApiKey key = apiKeyService.validateRawKey(apiKey);

            UsernamePasswordAuthenticationToken authToken =
                    new UsernamePasswordAuthenticationToken(
                            key, null, key.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authToken);
            return true;

        } catch (Exception e) {
            return false;
        }
    }

}

