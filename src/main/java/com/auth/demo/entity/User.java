package com.auth.demo.entity;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;

    private String name;

    // Null for OAuth users (Google login)
    private String password;

    @Enumerated(EnumType.STRING)
    private AuthProvider provider;

    // Google's unique user ID
    private String providerId;

    private String imageUrl;

    public enum AuthProvider {
        LOCAL, GOOGLE
    }
}
