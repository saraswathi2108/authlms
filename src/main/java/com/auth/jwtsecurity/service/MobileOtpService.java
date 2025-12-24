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
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private final JwtService jwtService;
    private final JavaMailSender mailSender;
    private final PasswordEncoder passwordEncoder;

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

    /* ---------------- SEND OTP ---------------- */

    public String sendOtpToUserPhone(String employeeId, String phoneNumber) throws Exception {
        if ((Objects.equals(employeeId, "np") || employeeId.isEmpty())
                && (Objects.equals(phoneNumber, "np") || phoneNumber.isEmpty())) {
            throw new BadRequestException("Either employeeId or phoneNumber must be provided");
        }

        Optional<User> user = employeeId.equals("np")
                ? userRepository.findByPhoneNumber(phoneNumber)
                : userRepository.findByUsername(employeeId.toLowerCase());

        if (user.isEmpty()) {
            throw new BadRequestException("No user found with the provided details");
        }

        if (user.get().getPhoneNumber() == null) {
            throw new BadRequestException("Phone number not linked to this account");
        }

        String id = sendOTP(user.get(), "PHONE");
        return rsaKeyUtil.rsaEncrypt(publicKey, id);
    }

    public String sendOtpToUserEmail(String employeeId, String email) throws Exception {
        if ((Objects.equals(employeeId, "np") || employeeId.isEmpty())
                && (Objects.equals(email, "np") || email.isEmpty())) {
            throw new BadRequestException("Either employeeId or email must be provided");
        }

        Optional<User> user = employeeId.equals("np")
                ? userRepository.findByEmail(email)
                : userRepository.findByUsername(employeeId.toLowerCase());

        if (user.isEmpty()) {
            throw new BadRequestException("No user found with the provided details");
        }

        if (user.get().getEmail() == null) {
            throw new BadRequestException("Email not linked to this account");
        }

        String id = sendOTP(user.get(), "EMAIL");
        return rsaKeyUtil.rsaEncrypt(publicKey, id);
    }

    /* ---------------- VERIFY OTP ---------------- */

    public TokenPair verifyOTP(String givenOtp, String key) throws Exception {

        String id = rsaKeyUtil.rsaDecrypt(privateKey, key);
        OtpStore otpStore = otpRepo.findById(id)
                .orElseThrow(() -> new BadRequestException("OTP not found"));

        if (otpStore.getExpiryTime().isBefore(Instant.now())) {
            throw new BadRequestException("OTP has expired");
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
                .withUsername(user.getUsername())
                .password(user.getPassword())
                .roles(String.valueOf(user.getRole()).replaceFirst("^ROLE_", ""))
                .build();

        Authentication authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        return jwtService.generateTokenPair(authentication);
    }

    /* ---------------- OTP CORE ---------------- */

    public String sendOTP(User user, String option) {

        String otpCode = generateNumericOtp(6);

        String otpMessage =
                "Your OTP for account verification is " + otpCode +
                        ". This OTP is valid for 5 minutes. Please do not share it with anyone.";

        String messageId = null;

        if ("PHONE".equals(option)) {
            messageId = sendSms(user.getPhoneNumber(), otpMessage);
        }

        if ("EMAIL".equals(option)) {
            messageId = sendEmail(user.getEmail(), otpMessage);
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

    /* ---------------- SMS & EMAIL ---------------- */

    public String sendSms(String phoneNumber, String message) {

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
        msg.setSubject("LMS Password Reset OTP");
        msg.setText(
                "Dear User,\n\n" +
                        message +
                        "\n\nIf you did not request this OTP, please ignore this email.\n\n" +
                        "Regards,\nLMS Support Team"
        );

        mailSender.send(msg);
        return UUID.randomUUID().toString();
    }

    /* ---------------- FORGOT PASSWORD ---------------- */

    public String sendForgotPasswordOtp(String email) throws Exception {

        Optional<User> userOpt = userRepository.findByEmail(email);
        if (userOpt.isEmpty()) {
            return "OTP_SENT";
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

        if (otpStore.getExpiryTime().isBefore(Instant.now())) {
            throw new RuntimeException("OTP expired");
        }

        if (otpStore.getVerified()) {
            throw new RuntimeException("OTP already used");
        }

        if (!otpStore.getOtp().equals(otp)) {
            throw new RuntimeException("Invalid OTP");
        }

        otpStore.setVerified(true);
        otpRepo.save(otpStore);

        User user = otpStore.getEmployeeID();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public String OtpSender(String userName, String mail, String phone) throws Exception {

        boolean noUserName = (userName == null || userName.equals("np") || userName.isBlank());
        boolean noEmail    = (mail == null || mail.equals("np") || mail.isBlank());
        boolean noPhone    = (phone == null || phone.equals("np") || phone.isBlank());

        if (noUserName && noEmail && noPhone) {
            throw new BadRequestException("At least one of username, email, or phone must be provided");
        }

        Optional<User> userOptional = Optional.empty();

        if (!noUserName) {
            userOptional = userRepository.findByUsername(userName.toLowerCase().trim());
        } else if (!noEmail) {
            userOptional = userRepository.findByEmail(mail.trim());
        } else if (!noPhone) {
            userOptional = userRepository.findByPhoneNumber(phone.trim());
        }

        if (userOptional.isEmpty()) {
            throw new BadRequestException("No user found with the provided details");
        }

        User user = userOptional.get();

        String otpType;

        if (!noEmail) {
            if (user.getEmail() == null) {
                throw new BadRequestException("Email not linked to this account");
            }
            otpType = "EMAIL";
        } else if (!noPhone) {
            if (user.getPhoneNumber() == null) {
                throw new BadRequestException("Phone number not linked to this account");
            }
            otpType = "PHONE";
        } else {
            throw new BadRequestException("Either email or phone must be provided");
        }

        String otpId = sendOTP(user, otpType);
        return rsaKeyUtil.rsaEncrypt(publicKey, otpId);
    }

}
