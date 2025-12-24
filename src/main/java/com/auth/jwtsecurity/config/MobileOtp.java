package com.auth.jwtsecurity.config;
import org.springframework.context.annotation.Bean;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class MobileOtp {


    @Value("${cloud.aws.region.static}")
    private String awsRegion;

    @Bean
    public SnsClient snsClient() {
        return SnsClient.builder().credentialsProvider(DefaultCredentialsProvider.create()).region(Region.of(awsRegion))
                .build();
    }
}
