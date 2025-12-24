package com.auth.jwtsecurity.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "user_session")
public class UserSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ONLY STUDENT
    @OneToOne
    @JoinColumn(name = "user_id", nullable = false, unique = true)
    private User user;

    @Column(name = "session_id", nullable = false, unique = true)
    private String sessionId;

    @Column(name = "device_type")
    private String deviceType; // MOBILE / WEB

    @Column(name = "last_login_time", nullable = false)
    private LocalDateTime lastLoginTime;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;
}
