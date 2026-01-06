//package com.auth.jwtsecurity.service;
//
//import com.auth.jwtsecurity.dto.TokenPair;
//import com.auth.jwtsecurity.model.AdminUser;
//import com.auth.jwtsecurity.model.User;
//import com.auth.jwtsecurity.repository.AdminUserRepository;
//import com.auth.jwtsecurity.repository.UserRepository;
//import com.auth.jwtsecurity.util.RsaKeyUtil;
//import io.jsonwebtoken.*;
//import jakarta.annotation.PostConstruct;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.security.core.Authentication;
//import org.springframework.stereotype.Service;
//
//import java.security.PrivateKey;
//import java.security.interfaces.RSAPublicKey;
//import java.util.*;
//
//@Service
//@Slf4j
//public class JwtService {
//
//    @Value("${app.jwt.expiration}")
//    private long jwtExpirationMs;
//
//    @Value("${app.jwt.refresh-expiration}")
//    private long refreshExpirationMs;
//
//    @Value("${app.jwt.private-key-path}")
//    private String privateKeyPath;
//
//    @Value("${app.jwt.public-key-path}")
//    private String publicKeyPath;
//
//    private final RsaKeyUtil rsaKeyUtil;
//    private final UserRepository userRepository;
//    private final AdminUserRepository adminUserRepository;
//
//    private PrivateKey privateKey;
//    private RSAPublicKey publicKey;
//
//    public JwtService(
//            RsaKeyUtil rsaKeyUtil,
//            UserRepository userRepository,
//            AdminUserRepository adminUserRepository
//    ) {
//        this.rsaKeyUtil = rsaKeyUtil;
//        this.userRepository = userRepository;
//        this.adminUserRepository = adminUserRepository;
//    }
//
//    @PostConstruct
//    public void initKeys() {
//        try {
//            privateKey = rsaKeyUtil.loadPrivateKey(privateKeyPath);
//            publicKey = (RSAPublicKey) rsaKeyUtil.loadPublicKey(publicKeyPath);
//        } catch (Exception e) {
//            throw new RuntimeException("Error loading RSA keys", e);
//        }
//    }
//
//    // =====================================================
//    // TOKEN PAIR (BACKWARD COMPATIBLE)
//    // =====================================================
//
//    public TokenPair generateTokenPair(Authentication authentication) {
//        return generateTokenPair(authentication, null);
//    }
//
//    // ✅ sessionId OPTIONAL (student only)
//    public TokenPair generateTokenPair(Authentication authentication, String sessionId) {
//        String accessToken = generateToken(authentication, jwtExpirationMs, sessionId, new HashMap<>());
//        String refreshToken = generateRefreshToken(authentication);
//        return new TokenPair(accessToken, refreshToken);
//    }
//
//    public String generateAccessToken(Authentication authentication) {
//        return generateToken(authentication, jwtExpirationMs, null, new HashMap<>());
//    }
//
//    public String generateRefreshToken(Authentication authentication) {
//        Map<String, String> claims = new HashMap<>();
//        claims.put("tokenType", "refresh");
//        return generateToken(authentication, refreshExpirationMs, null, claims);
//    }
//
//    // =====================================================
//    // CORE TOKEN GENERATION (SAFE)
//    // =====================================================
//
//    private String generateToken(
//            Authentication authentication,
//            long expirationInMs,
//            String sessionId,
//            Map<String, String> additionalClaims
//    ) {
//
//        String email = authentication.getName().toLowerCase().trim();
//
//        Long userId;
//        String fullName;
//        String role;
//
//        // ✅ ADMIN (EMAIL)
//        Optional<AdminUser> adminOpt = adminUserRepository.findByEmail(email);
//        if (adminOpt.isPresent()) {
//            AdminUser admin = adminOpt.get();
//            userId = admin.getId();
//            fullName = admin.getEmail(); // SAFE
//            role = admin.getRole().name().replace("ROLE_", "");
//        }
//        // ✅ STUDENT (EMAIL)
//        else {
//            User user = userRepository.findByEmail(email)
//                    .orElseThrow(() -> new RuntimeException("User not found"));
//
//            userId = user.getId();
//            fullName = user.getFullName();
//            role = user.getRole().name().replace("ROLE_", "");
//        }
//
//        Date now = new Date();
//        Date expiryDate = new Date(now.getTime() + expirationInMs);
//
//        Map<String, Object> claims = new HashMap<>(additionalClaims);
//        claims.put("userId", userId);
//        claims.put("fullName", fullName);
//        claims.put("roles", List.of(role));
//
//        // 🔥 SAFE ADDITION (course service will ignore)
//        if (sessionId != null) {
//            claims.put("sessionId", sessionId);
//        }
//
//        return Jwts.builder()
//                .header().add("typ", "JWT").and()
//                .subject(email)                    // SAME AS BEFORE
//                .issuer("auth-service")
//                .claims(claims)
//                .issuedAt(now)
//                .expiration(expiryDate)
//                .signWith(privateKey, SignatureAlgorithm.RS256)
//                .compact();
//    }
//
//    // =====================================================
//    // TOKEN UTILITIES (UNCHANGED)
//    // =====================================================
//
//    public boolean isValidToken(String token) {
//        try {
//            extractAllClaims(token);
//            return true;
//        } catch (Exception e) {
//            return false;
//        }
//    }
//
//    public boolean isRefreshToken(String token) {
//        Claims claims = extractAllClaims(token);
//        return "refresh".equals(claims.get("tokenType"));
//    }
//
//    public String extractUsernameFromToken(String token) {
//        return extractAllClaims(token).getSubject();
//    }
//
//    public Claims extractAllClaims(String token) {
//        return Jwts.parser()
//                .verifyWith(publicKey)
//                .build()
//                .parseSignedClaims(token)
//                .getPayload();
//    }
//
//    public RSAPublicKey getRsaPublicKey() {
//        return publicKey;
//    }
//
//    public byte[] getEncodedPublicKey() {
//        return publicKey.getEncoded();
//    }
//}

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

    @PostConstruct
    public void initKeys() {
        try {
            privateKey = rsaKeyUtil.loadPrivateKey(privateKeyPath);
            publicKey = (RSAPublicKey) rsaKeyUtil.loadPublicKey(publicKeyPath);
        } catch (Exception e) {
            throw new RuntimeException("Error loading RSA keys", e);
        }
    }



    public TokenPair generateTokenPair(Authentication authentication) {
        return generateTokenPair(authentication, null);
    }

    public TokenPair generateTokenPair(Authentication authentication, String sessionId) {
        String accessToken = generateToken(authentication, jwtExpirationMs, sessionId, new HashMap<>());
        String refreshToken = generateRefreshToken(authentication);
        return new TokenPair(accessToken, refreshToken);
    }

    public String generateAccessToken(Authentication authentication) {
        return generateToken(authentication, jwtExpirationMs, null, new HashMap<>());
    }

    public String generateRefreshToken(Authentication authentication) {
        Map<String, String> claims = new HashMap<>();
        claims.put("tokenType", "refresh");
        return generateToken(authentication, refreshExpirationMs, null, claims);
    }



    private String generateToken(
            Authentication authentication,
            long expirationInMs,
            String sessionId,
            Map<String, String> additionalClaims
    ) {

        String email = authentication.getName().toLowerCase().trim();

        Long userId;
        String fullName;
        String role;
        boolean isFirstLogin = false;

        Optional<AdminUser> adminOpt = adminUserRepository.findByEmail(email);
        if (adminOpt.isPresent()) {
            AdminUser admin = adminOpt.get();
            userId = admin.getId();
            fullName = admin.getEmail(); // SAFE
            role = admin.getRole().name().replace("ROLE_", "");
        }
        else {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            userId = user.getId();
            fullName = user.getFullName();
            role = user.getRole().name().replace("ROLE_", "");


            isFirstLogin = user.isForcePasswordChange();
        }

        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + expirationInMs);

        Map<String, Object> claims = new HashMap<>(additionalClaims);
        claims.put("userId", userId);
        claims.put("fullName", fullName);
        claims.put("roles", List.of(role));

        claims.put("isFirstLogin", isFirstLogin);

        if (sessionId != null) {
            claims.put("sessionId", sessionId);
        }

        return Jwts.builder()
                .header().add("typ", "JWT").and()
                .subject(email)
                .issuer("auth-service")
                .claims(claims)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }


    public boolean isValidToken(String token) {
        try {
            extractAllClaims(token);
            return true;
        } catch (Exception e) {
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
        return Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public RSAPublicKey getRsaPublicKey() {
        return publicKey;
    }

    public byte[] getEncodedPublicKey() {
        return publicKey.getEncoded();
    }
}
