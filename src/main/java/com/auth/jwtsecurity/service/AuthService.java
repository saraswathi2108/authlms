package com.auth.jwtsecurity.service;

import ch.qos.logback.core.net.SyslogOutputStream;
//import com.auth.jwtsecurity.Client.TicketsUpdate;
import com.auth.jwtsecurity.dto.*;
//import com.auth.jwtsecurity.dto.RefreshTokenRequest;
import com.auth.jwtsecurity.model.AdminUser;
import com.auth.jwtsecurity.model.Role;
import com.auth.jwtsecurity.model.User;
import com.auth.jwtsecurity.repository.AdminUserRepository;
import com.auth.jwtsecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.regex.Pattern;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
//    private final TicketsUpdate ticketsUpdate;

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    );
    private final AdminUserRepository adminUserRepository;

    @Transactional
    public void registerUser(@Valid RegisterRequest request) {

        String username = request.getUsername().toLowerCase().trim();

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username is already in use");
        }

        if (!isStrongPassword(request.getPassword())) {
            throw new IllegalArgumentException("Weak password");
        }

        User user = User.builder()
                .fullName(request.getFullName())
                .username(username)
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .phoneNumber(request.getPhoneNumber())
                .panNumber(request.getPanNumber())
                .collegeName(request.getCollegeName())
                .collegeRollNumber(request.getCollegeRollNumber())
                .passoutYear(request.getPassoutYear())
                .role(Role.ROLE_STUDENT)
                .build();

//       Tickets tickets = Tickets.builder()
//                       .employeeId(username.toUpperCase().trim())
//                               .roles(registerRequest.getRole())
//                                       .build();
//       ResponseEntity<Tickets> re = ticketsUpdate.createAuth(tickets);
//       if (!re.getStatusCode().is2xxSuccessful()) throw new RuntimeException("Cant Update Tickets branch");
        userRepository.save(user);
    }

    public void deleteUser(String id) {
        User user = userRepository.findByUsername(id)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
//        ResponseEntity<Void> re = ticketsUpdate.deleteAuth(user.getUsername().toUpperCase());
//        if (!re.getStatusCode().is2xxSuccessful()) throw new RuntimeException("Cant Update Tickets branch");
        userRepository.delete(user);
    }

    public void updateUser(String id, UpdateRequest request) {
        User user = userRepository.findByUsername(id.toLowerCase().trim())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (request.getUsername() != null)
            user.setUsername(request.getUsername().toLowerCase().trim());

        if (request.getFullName() != null)
            user.setFullName(request.getFullName());

        if (request.getPassword() != null)
            user.setPassword(passwordEncoder.encode(request.getPassword()));

        if (request.getPhoneNumber() != null)
            user.setPhoneNumber(request.getPhoneNumber());

        if (request.getEmail() != null)
            user.setEmail(request.getEmail());

//        Tickets tickets = Tickets.builder()
//                .employeeId(user.getUsername().toUpperCase())
//                .roles(registerRequest.getRole())
//                .build();
//        ResponseEntity<Tickets> re = ticketsUpdate.updateAuth(user.getUsername().toUpperCase(),tickets);
//        if (!re.getStatusCode().is2xxSuccessful()) throw new RuntimeException("Cant Update Tickets branch");
        userRepository.save(user);
    }

    public TokenPair login(@Valid LoginRequest loginRequest) {

        String email = loginRequest.getEmail().trim();

        Authentication authentication;

        // 1️⃣ Try ADMIN login
        Optional<AdminUser> adminOpt = adminUserRepository.findByEmail(email);

        if (adminOpt.isPresent()) {
            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            adminOpt.get().getUsername(),
                            loginRequest.getPassword()
                    )
            );
        }
        // 2️⃣ Else try STUDENT login
        else {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password"));

            authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            user.getUsername(),
                            loginRequest.getPassword()
                    )
            );
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        return jwtService.generateTokenPair(authentication);
    }


    public TokenPair refreshTokenFromCookie(String refreshToken) {
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token");
        }

        String username = jwtService.extractUsernameFromToken(refreshToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (userDetails == null) {
            throw new IllegalArgumentException("User not found");
        }

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                null,
                userDetails.getAuthorities()
        );

        String accessToken = jwtService.generateAccessToken(authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    private boolean isStrongPassword(String password) {
        return PASSWORD_PATTERN.matcher(password).matches();
    }
    @Transactional
    public void createAdmin(@Valid CreateAdminRequest request) {

        String username = request.getUsername().toLowerCase().trim();

        if (userRepository.existsByUsername(username)) {
            throw new IllegalArgumentException("Username already exists");
        }

        if (!isStrongPassword(request.getPassword())) {
            throw new IllegalArgumentException("Weak password");
        }

        AdminUser admin = AdminUser.builder()
                .username(request.getUsername().toLowerCase().trim())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .role(Role.ROLE_ADMIN)
                .build();

        adminUserRepository.save(admin);
    }

    @Transactional
    public void changePassword(
            ChangePasswordRequest request,
            Authentication authentication
    ) {

        String username = authentication.getName().toLowerCase().trim();

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new IllegalArgumentException("New password and confirm password do not match");
        }

        Optional<AdminUser> adminOpt = adminUserRepository.findByUsername(username);
        if (adminOpt.isPresent()) {

            AdminUser admin = adminOpt.get();

            if (!passwordEncoder.matches(request.getOldPassword(), admin.getPassword())) {
                throw new IllegalArgumentException("Old password is incorrect");
            }

            admin.setPassword(passwordEncoder.encode(request.getNewPassword()));
            adminUserRepository.save(admin);
            return;
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!passwordEncoder.matches(request.getOldPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Old password is incorrect");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }


}
