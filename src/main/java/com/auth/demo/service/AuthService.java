package com.auth.demo.service;

import com.auth.demo.dto.AuthDto.*;
import com.auth.demo.entity.User;
import com.auth.demo.repository.UserRepository;
import com.auth.demo.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final AuthenticationManager authenticationManager;

    public MessageResponse signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already registered");
        }

        User user = User.builder()
                .name(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(User.AuthProvider.LOCAL)
                .build();

        userRepository.save(user);
        return new MessageResponse("User registered successfully!");
    }

    public AuthResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
        );

        String token = tokenProvider.generateToken(request.getEmail());
        User user = userRepository.findByEmail(request.getEmail()).orElseThrow();

        return new AuthResponse(token, user.getEmail(), user.getName(), user.getImageUrl());
    }

    public AuthResponse getMe(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));
        return new AuthResponse(null, user.getEmail(), user.getName(), user.getImageUrl());
    }
}
