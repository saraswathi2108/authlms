package com.auth.jwtsecurity.repository;

import com.auth.jwtsecurity.model.User;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
//    Optional<User> findByUsername(String username);
    @Query(nativeQuery = true, value = "SELECT * FROM auth.application_user AS A WHERE A.email = :email")
    Optional<User> findByEmail(String email);
    @Query(nativeQuery = true, value = "SELECT * FROM auth.application_user AS A WHERE A.phone_number = :phoneNumber")
    Optional<User> findByPhoneNumber(String phoneNumber);

    boolean existsByEmail(@NotBlank @Email String email);
    @Query("select u.email from User u where u.email in :emails")
    List<String> findExistingEmails(@Param("emails") List<String> emails);

    @Query("select u.panNumber from User u where u.panNumber in :pans")
    List<String> findExistingPans(@Param("pans") List<String> pans);

    boolean existsByPanNumber(@NotBlank @Size(min = 10, max = 10) String panNumber);
}
