package com.auth.mini.controller;


import com.auth.mini.config.JwtUtil;
import com.auth.mini.dto.AuthRequest;
import com.auth.mini.dto.AuthResponse;
import com.auth.mini.entity.User;
import com.auth.mini.service.UserService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService userService;
    private final JwtUtil jwtUtil;

    public AuthController(UserService userService, JwtUtil jwtUtil) {
        this.userService = userService;
        this.jwtUtil = jwtUtil;
    }

    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AuthRequest request) {

        User existing = userService.findByEmail(request.getEmail());
        if (existing != null) {
            return ResponseEntity
                    .badRequest()
                    .body("Email already used");
        }

        User created = userService.createUser(
                request.getEmail(),
                request.getPassword(),
                request.getName()
        );

        return ResponseEntity.ok(
                Map.of(
                        "id", created.getId(),
                        "email", created.getEmail()
                )
        );
    }


    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {

        User user = userService.findByEmail(request.getEmail());
        if (user == null || !userService.checkPassword(user, request.getPassword())) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }

        String token = jwtUtil.generateToken(
                user.getId().toString(),
                Map.of(
                        "email", user.getEmail(),
                        "role", user.getRole()
                )
        );

        return ResponseEntity.ok(new AuthResponse(token));
    }
}


