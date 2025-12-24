package com.auth.jwtsecurity.service;

import com.auth.jwtsecurity.dto.TokenPair;
import com.auth.jwtsecurity.model.AdminUser;
import com.auth.jwtsecurity.model.User;
import com.auth.jwtsecurity.repository.AdminUserRepository;
import com.auth.jwtsecurity.repository.UserRepository;
import com.auth.jwtsecurity.util.RsaKeyUtil;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
@Slf4j
public class JwtService {

    @Value("${app.jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshExpirationMs;

    @Value("${app.jwt.private-key-path}")
    private String privateKeyPath;

    @Value("${app.jwt.public-key-path}")
    private String publicKeyPath;

    private final RsaKeyUtil rsaKeyUtil;
    private final UserRepository userRepository;
    private final AdminUserRepository adminUserRepository;

    private PrivateKey privateKey;
    private RSAPublicKey publicKey;

    public JwtService(
            RsaKeyUtil rsaKeyUtil,
            UserRepository userRepository,
            AdminUserRepository adminUserRepository
    ) {
        this.rsaKeyUtil = rsaKeyUtil;
        this.userRepository = userRepository;
        this.adminUserRepository = adminUserRepository;
    }

    // 🔐 Load RSA keys
    @PostConstruct
    public void initKeys() {
        try {
            privateKey = rsaKeyUtil.loadPrivateKey(privateKeyPath);
            publicKey = (RSAPublicKey) rsaKeyUtil.loadPublicKey(publicKeyPath);
        } catch (Exception e) {
            log.error("Failed to load RSA keys", e);
            throw new RuntimeException("Error loading RSA keys", e);
        }
    }

    // 🔐 Generate Access + Refresh Token
    public TokenPair generateTokenPair(Authentication authentication) {
        String accessToken = generateToken(authentication, jwtExpirationMs, new HashMap<>());
        String refreshToken = generateRefreshToken(authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, jwtExpirationMs, new HashMap<>());
    }

    public String generateRefreshToken(Authentication authentication) {
        Map<String, String> claims = new HashMap<>();
        claims.put("tokenType", "refresh");
        return generateToken(authentication, refreshExpirationMs, claims);
    }

    // 🔥 CORE METHOD (ADMIN + STUDENT)
    private String generateToken(
            Authentication authentication,
            long expirationInMs,
            Map<String, String> additionalClaims
    ) {

        String username = authentication.getName();

        Long userId;
        String fullName;
        String role;

        // ✅ CHECK ADMIN FIRST
        Optional<AdminUser> adminOpt = adminUserRepository.findByUsername(username);
        if (adminOpt.isPresent()) {
            AdminUser admin = adminOpt.get();
            userId = admin.getId();
            fullName = admin.getUsername(); // or admin.getEmail()
            role = admin.getRole().name().replace("ROLE_", "");
        }
        // ✅ ELSE STUDENT
        else {
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            userId = user.getId();
            fullName = user.getFullName();
            role = user.getRole().name().replace("ROLE_", "");
        }

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationInMs);

        Map<String, Object> claims = new HashMap<>(additionalClaims);
        claims.put("userId", userId);
        claims.put("fullName", fullName);
        claims.put("roles", List.of(role));

        return Jwts.builder()
                .header().add("typ", "JWT").and()
                .subject(username)              // SAME for admin & student
                .issuer("auth-service")
                .claims(claims)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    // 🔍 TOKEN VALIDATION
    public boolean isValidToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
            log.warn("Invalid token: {}", e.getMessage());
            return false;
        }
    }

    public boolean isRefreshToken(String token) {
        Claims claims = extractAllClaims(token);
        return "refresh".equals(claims.get("tokenType"));
    }

    public String extractUsernameFromToken(String token) {
        return extractAllClaims(token).getSubject();
    }

    public Claims extractAllClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new RuntimeException("Token expired");
        } catch (JwtException e) {
            throw new RuntimeException("Invalid token");
        }
    }

    public String generatePasswordResetToken(String email) {
        return Jwts.builder()
                .subject(email)
                .claim("purpose", "RESET_PASSWORD")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public void validatePasswordResetToken(String token) {
        Claims claims = extractAllClaims(token);
        if (!"RESET_PASSWORD".equals(claims.get("purpose", String.class))) {
            throw new RuntimeException("Invalid password reset token");
        }
    }

    public RSAPublicKey getRsaPublicKey() {
        return publicKey;
    }

    public byte[] getEncodedPublicKey() {
        return publicKey.getEncoded();
    }
}
