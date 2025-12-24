package com.auth.jwtsecurity.service;

import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;

    @Async
    public void sendStudentCredentials(String toEmail, String password) {

        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("LMS Login Credentials");
        message.setText(
                "Hello,\n\n" +
                        "Your LMS account has been created.\n\n" +
                        "Login Email: " + toEmail + "\n" +
                        "Temporary Password: " + password + "\n\n" +
                        "⚠ Please change your password after first login.\n\n" +
                        "Regards,\nLMS Team"
        );

        mailSender.send(message);
    }
}
