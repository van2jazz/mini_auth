package com.auth.mini.service;


import com.auth.mini.entity.User;
import com.auth.mini.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;


import java.time.Instant;
import java.util.UUID;


@Service
public class UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    public User createUser(String email, String plainPassword, String name) {
        var u = User.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(plainPassword))
                .name(name)
                .createdAt(Instant.now())
                .role("ROLE_USER")
                .build();
        return userRepository.save(u);
    }


    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }


    public boolean checkPassword(User user, String plainPassword) {
        return passwordEncoder.matches(plainPassword, user.getPasswordHash());
    }

    public UserDetails loadUserById(String id) {
        UUID uuid = UUID.fromString(id);

        return userRepository.findById(uuid)
                .map(u -> (UserDetails) u)
                .orElseThrow(() -> new RuntimeException("User not found"));
    }
}
