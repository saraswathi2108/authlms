package com.auth.jwtsecurity.repository;

import com.auth.jwtsecurity.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Boolean existsByUsername(String username);
    @Query(nativeQuery = true, value = "SELECT * FROM auth.application_user AS A WHERE A.email = :email")
    Optional<User> findByEmail(String email);
    @Query(nativeQuery = true, value = "SELECT * FROM auth.application_user AS A WHERE A.phone_number = :phoneNumber")
    Optional<User> findByPhoneNumber(String phoneNumber);
}
