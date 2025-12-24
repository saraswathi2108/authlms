package com.auth.jwtsecurity.service;

import com.auth.jwtsecurity.dto.TokenPair;
import com.auth.jwtsecurity.model.OtpStore;
import com.auth.jwtsecurity.model.User;
import com.auth.jwtsecurity.repository.OtpRepo;
import com.auth.jwtsecurity.repository.UserRepository;
import com.auth.jwtsecurity.util.RsaKeyUtil;
import jakarta.annotation.PostConstruct;
import org.apache.coyote.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;
import software.amazon.awssdk.services.sns.model.PublishRequest;
import software.amazon.awssdk.services.sns.model.PublishResponse;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class MobileOtpService {

    private final SnsClient snsClient;
    private final UserRepository userRepository;
    private final OtpRepo otpRepo;
    private final RsaKeyUtil rsaKeyUtil;
    private final JwtService jwtService;
    private final JavaMailSender mailSender;
    private final PasswordEncoder passwordEncoder;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Autowired
    public MobileOtpService(
            SnsClient snsClient,
            UserRepository userRepository,
            OtpRepo otpRepo,
            RsaKeyUtil rsaKeyUtil,
            JwtService jwtService,
            JavaMailSender mailSender,
            PasswordEncoder passwordEncoder
    ) {
        this.snsClient = snsClient;
        this.userRepository = userRepository;
        this.otpRepo = otpRepo;
        this.rsaKeyUtil = rsaKeyUtil;
        this.jwtService = jwtService;
        this.mailSender = mailSender;
        this.passwordEncoder = passwordEncoder;
    }

    @PostConstruct
    public void initKeys() throws Exception {
        this.publicKey = rsaKeyUtil.loadPublicKey("classpath:keys/public_key.pem");
        this.privateKey = rsaKeyUtil.loadPrivateKey("classpath:keys/private_key.pem");
    }

    /* ================= SEND OTP ================= */

    public String sendOtpToUserPhone(String email, String phoneNumber) throws Exception {

        if ((email == null || email.equals("np")) &&
                (phoneNumber == null || phoneNumber.equals("np"))) {
            throw new BadRequestException("Email or phone number must be provided");
        }

        Optional<User> user = (email != null && !email.equals("np"))
                ? userRepository.findByEmail(email.toLowerCase())
                : userRepository.findByPhoneNumber(phoneNumber);

        if (user.isEmpty()) {
            throw new BadRequestException("User not found");
        }

        if (user.get().getPhoneNumber() == null) {
            throw new BadRequestException("Phone number not linked");
        }

        String otpId = sendOTP(user.get(), "PHONE");
        return rsaKeyUtil.rsaEncrypt(publicKey, otpId);
    }

    public String sendOtpToUserEmail(String email) throws Exception {

        if (email == null || email.equals("np")) {
            throw new BadRequestException("Email must be provided");
        }

        User user = userRepository.findByEmail(email.toLowerCase())
                .orElseThrow(() -> new BadRequestException("User not found"));

        if (user.getEmail() == null) {
            throw new BadRequestException("Email not linked");
        }

        String otpId = sendOTP(user, "EMAIL");
        return rsaKeyUtil.rsaEncrypt(publicKey, otpId);
    }

    /* ================= VERIFY OTP ================= */

    public TokenPair verifyOTP(String givenOtp, String encryptedKey) throws Exception {

        String otpId = rsaKeyUtil.rsaDecrypt(privateKey, encryptedKey);

        OtpStore otpStore = otpRepo.findById(otpId)
                .orElseThrow(() -> new BadRequestException("OTP not found"));

        if (otpStore.getExpiryTime().isBefore(Instant.now())) {
            throw new BadRequestException("OTP expired");
        }

        if (otpStore.getVerified()) {
            throw new BadRequestException("OTP already used");
        }

        if (!otpStore.getOtp().equals(givenOtp)) {
            throw new BadRequestException("Invalid OTP");
        }

        otpStore.setVerified(true);
        otpRepo.save(otpStore);

        User user = otpStore.getEmployeeID();

        UserDetails userDetails = org.springframework.security.core.userdetails.User
                .withUsername(user.getEmail())
                .password(user.getPassword())
                .roles(user.getRole().name().replace("ROLE_", ""))
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwtService.generateTokenPair(authentication);
    }

    /* ================= OTP CORE ================= */

    private String sendOTP(User user, String channel) {

        String otpCode = generateNumericOtp(6);

        String message =
                "Your OTP is " + otpCode +
                        ". Valid for 5 minutes. Do not share.";

        String messageId;

        if ("PHONE".equals(channel)) {
            messageId = sendSms(user.getPhoneNumber(), message);
        } else {
            messageId = sendEmail(user.getEmail(), message);
        }

        OtpStore otpStore = OtpStore.builder()
                .otp(otpCode)
                .messageId(messageId)
                .employeeID(user)
                .sentTime(LocalDateTime.now())
                .expiryTime(Instant.now().plusSeconds(300))
                .verified(false)
                .build();

        otpRepo.save(otpStore);
        return messageId;
    }

    private static String generateNumericOtp(int length) {
        SecureRandom random = new SecureRandom();
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < length; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    /* ================= SMS & EMAIL ================= */

    private String sendSms(String phoneNumber, String message) {

        Map<String, MessageAttributeValue> attributes = new HashMap<>();
        attributes.put("AWS.SNS.SMS.SMSType",
                MessageAttributeValue.builder()
                        .dataType("String")
                        .stringValue("Transactional")
                        .build());

        PublishRequest request = PublishRequest.builder()
                .phoneNumber(phoneNumber)
                .message(message)
                .messageAttributes(attributes)
                .build();

        PublishResponse response = snsClient.publish(request);
        return response.messageId();
    }

    private String sendEmail(String email, String message) {

        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(email);
        msg.setSubject("LMS OTP Verification");
        msg.setText(message);

        mailSender.send(msg);
        return UUID.randomUUID().toString();
    }

    /* ================= FORGOT PASSWORD ================= */

    public String sendForgotPasswordOtp(String email) throws Exception {

        Optional<User> userOpt = userRepository.findByEmail(email.toLowerCase());
        if (userOpt.isEmpty()) {
            return "OTP_SENT"; // security: do not reveal existence
        }

        String otpId = sendOTP(userOpt.get(), "EMAIL");
        return rsaKeyUtil.rsaEncrypt(publicKey, otpId);
    }

    @Transactional
    public void resetPasswordWithOtp(
            String encryptedOtpToken,
            String otp,
            String newPassword,
            String confirmPassword
    ) throws Exception {

        if (!newPassword.equals(confirmPassword)) {
            throw new IllegalArgumentException("Passwords do not match");
        }

        String otpId = rsaKeyUtil.rsaDecrypt(privateKey, encryptedOtpToken);

        OtpStore otpStore = otpRepo.findById(otpId)
                .orElseThrow(() -> new RuntimeException("OTP not found"));

        if (!otpStore.getOtp().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }

        otpStore.setVerified(true);
        otpRepo.save(otpStore);

        User user = otpStore.getEmployeeID();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
}
