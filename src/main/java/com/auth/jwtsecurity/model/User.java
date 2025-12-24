package com.auth.jwtsecurity.model;

import jakarta.persistence.*;
import lombok.*;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(
        name = "application_user",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = "username"),
                @UniqueConstraint(columnNames = "email"),
                @UniqueConstraint(columnNames = "phone_number"),
                @UniqueConstraint(columnNames = "pan_number"),
                @UniqueConstraint(columnNames = {"college_name", "college_roll_number"})
        }
)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // ===== BASIC DETAILS =====

    @Column(name = "full_name", nullable = false, length = 100)
    private String fullName;

    @Column(nullable = false, unique = true, length = 50)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(name = "phone_number", nullable = false, unique = true, length = 15)
    private String phoneNumber;

    @Column(nullable = false, unique = true, length = 150)
    private String email;


    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Role role;   // ALWAYS ROLE_STUDENT


    @Column(name = "pan_number", nullable = false, unique = true, length = 10)
    private String panNumber;

    // ===== COLLEGE DETAILS =====

    @Column(name = "college_name", nullable = false, length = 150)
    private String collegeName;

    @Column(name = "college_roll_number", nullable = false, length = 50)
    private String collegeRollNumber;

    @Column(name = "passout_year", nullable = false)
    private Integer passoutYear;


}
