package com.auth.jwtsecurity.repository;


import com.auth.jwtsecurity.model.OtpStore;
import io.micrometer.core.instrument.Meter.Id;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OtpRepo extends JpaRepository<OtpStore, String> {

    Optional<OtpStore> findById(String s);
}