package com.auth.jwtsecurity.service;

import com.auth.jwtsecurity.dto.*;
import com.auth.jwtsecurity.exception.AlreadyLoggedInException;
import com.auth.jwtsecurity.model.*;
import com.auth.jwtsecurity.repository.*;
import org.springframework.transaction.annotation.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final AdminUserRepository adminUserRepository;
    private final UserSessionRepository userSessionRepository;

    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final EmailService emailService;

    private static final Pattern PASSWORD_PATTERN =
            Pattern.compile("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&]).{8,}$");


    @Transactional
    public void bulkCreateStudents(List<BulkStudentRequest> students) {

        List<String> emails = students.stream()
                .map(s -> s.getEmail().toLowerCase().trim())
                .toList();

        List<String> pans = students.stream()
                .map(BulkStudentRequest::getPanNumber)
                .toList();

        List<String> existingEmails = userRepository.findExistingEmails(emails);
        List<String> existingPans = userRepository.findExistingPans(pans);

        List<User> users = new ArrayList<>();
        Map<String, String> emailPasswordMap = new HashMap<>();

        String defaultPassword = PasswordUtil.generateRandomPassword();
        String encodedPassword = passwordEncoder.encode(defaultPassword);

        for (BulkStudentRequest req : students) {

            if (existingEmails.contains(req.getEmail())
                    || existingPans.contains(req.getPanNumber())) {
                continue;
            }

            User user = User.builder()
                    .fullName(req.getFullName())
                    .email(req.getEmail().toLowerCase().trim())
                    .phoneNumber(req.getPhoneNumber())
                    .panNumber(req.getPanNumber())
                    .collegeName(req.getCollegeName())
                    .collegeRollNumber(req.getCollegeRollNumber())
                    .passoutYear(req.getPassoutYear())
                    .password(encodedPassword)
                    .role(Role.ROLE_STUDENT)
                    .forcePasswordChange(true)
                    .isActive(true)
                    .createdAt(LocalDateTime.now()) // if not using auditing
                    .build();

            users.add(user);
            emailPasswordMap.put(user.getEmail(), defaultPassword);
        }

        // 4️⃣ Single DB call
        userRepository.saveAll(users);

        // 5️⃣ Send emails AFTER DB commit
        emailPasswordMap.forEach((email, pwd) ->
                emailService.sendStudentCredentials(email, pwd)
        );
    }


    // =====================================================
    // LOGIN (ADMIN + STUDENT)
    // =====================================================

    public TokenPair login(@Valid LoginRequest loginRequest) {

        String email = loginRequest.getEmail().toLowerCase().trim();

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        email,
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        Optional<User> studentOpt = userRepository.findByEmail(email);
        if (studentOpt.isPresent()) {

            User student = studentOpt.get();

            if (!student.isActive()) {
                throw new IllegalStateException("Account is deactivated");
            }

            // 🔥 CHECK EXISTING SESSION (NO DELETE)
            if (userSessionRepository.existsByUserId(student.getId())) {
                throw new AlreadyLoggedInException(
                        "User already logged in on another device"
                );
            }

            String sessionId = UUID.randomUUID().toString();

            UserSession session = UserSession.builder()
                    .user(student)
                    .sessionId(sessionId)
                    .lastLoginTime(LocalDateTime.now())
                    .build();

            userSessionRepository.save(session);

            return jwtService.generateTokenPair(authentication, sessionId);
        }

        // ADMIN → no restriction
        return jwtService.generateTokenPair(authentication, null);
    }



    @Transactional
    public void logout(Authentication authentication) {

        String email = authentication.getName().toLowerCase().trim();

        userRepository.findByEmail(email)
                .ifPresent(user ->
                        userSessionRepository.deleteByUserId(user.getId())
                );
    }


    @Transactional
    public void deleteUserByEmail(String email) {
        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        userSessionRepository.deleteByUserId(user.getId());
        userRepository.delete(user);
    }

    @Transactional
    public void updateUserByEmail(String email, UpdateRequest request) {

        User user = userRepository.findByEmail(email.toLowerCase().trim())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (request.getFullName() != null)
            user.setFullName(request.getFullName());

        if (request.getPhoneNumber() != null)
            user.setPhoneNumber(request.getPhoneNumber());

        if (request.getEmail() != null)
            user.setEmail(request.getEmail().toLowerCase().trim());

        userRepository.save(user);
    }


    @Transactional
    public void changePassword(ChangePasswordRequest request,
                               Authentication authentication) {

        String email = authentication.getName().toLowerCase().trim();

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        if (!PASSWORD_PATTERN.matcher(request.getNewPassword()).matches()) {
            throw new IllegalArgumentException("Weak password");
        }

        Optional<AdminUser> adminOpt = adminUserRepository.findByEmail(email);
        if (adminOpt.isPresent()) {

            AdminUser admin = adminOpt.get();

            if (request.getOldPassword() == null ||
                    !passwordEncoder.matches(request.getOldPassword(), admin.getPassword())) {
                throw new IllegalArgumentException("Old password incorrect");
            }

            admin.setPassword(passwordEncoder.encode(request.getNewPassword()));
            adminUserRepository.save(admin);
            return;
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (user.isForcePasswordChange()) {

            user.setPassword(passwordEncoder.encode(request.getNewPassword()));

            user.setForcePasswordChange(false);

            userRepository.save(user);
            return;
        }

        if (request.getOldPassword() == null ||
                !passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Old password incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    @Transactional
    public void createAdmin(@Valid CreateAdminRequest request) {

        String email = request.getEmail().toLowerCase().trim();

        if (adminUserRepository.existsByEmail(email)) {
            throw new IllegalArgumentException("Admin already exists");
        }

        if (!PASSWORD_PATTERN.matcher(request.getPassword()).matches()) {
            throw new IllegalArgumentException("Weak password");
        }

        AdminUser admin = AdminUser.builder()
                .email(email)
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.ROLE_ADMIN)
                .build();

        adminUserRepository.save(admin);
    }


    public TokenPair refreshTokenFromCookie(String refreshToken) {

        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String email = jwtService.extractUsernameFromToken(refreshToken);

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(email, null, List.of());

        String accessToken = jwtService.generateAccessToken(authentication);
        return new TokenPair(accessToken, refreshToken);
    }
}
