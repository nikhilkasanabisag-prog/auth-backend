package com.auth.demo.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

public class AuthDto {

    @Data
    public static class SignupRequest {
        @NotBlank
        private String name;

        @Email
        @NotBlank
        private String email;

        @NotBlank
        @Size(min = 6, message = "Password must be at least 6 characters")
        private String password;
    }

    @Data
    public static class LoginRequest {
        @Email
        @NotBlank
        private String email;

        @NotBlank
        private String password;
    }

    @Data
    @lombok.AllArgsConstructor
    public static class AuthResponse {
        private String token;
        private String email;
        private String name;
        private String imageUrl;
    }

    @Data
    @lombok.AllArgsConstructor
    public static class MessageResponse {
        private String message;
    }
}
