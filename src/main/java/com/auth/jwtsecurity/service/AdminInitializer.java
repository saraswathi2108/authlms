package com.auth.jwtsecurity.service;

import com.auth.jwtsecurity.model.AdminUser;
import com.auth.jwtsecurity.model.Role;
import com.auth.jwtsecurity.model.User;
import com.auth.jwtsecurity.repository.AdminUserRepository;
import com.auth.jwtsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.password.PasswordEncoder;
@Configuration
@RequiredArgsConstructor


public class AdminInitializer implements CommandLineRunner {

    private final AdminUserRepository adminRepo;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {

        if (adminRepo.findByUsername("admin").isEmpty()) {

            AdminUser admin = AdminUser.builder()
                    .username("admin")
                    .password(passwordEncoder.encode("Admin@123"))
                    .email("admin@company.com")
                    .role(Role.ROLE_ADMIN)
                    .build();

            adminRepo.save(admin);
        }
    }
}
