package com.auth.jwtsecurity.repository;

import com.auth.jwtsecurity.model.UserSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    Optional<UserSession> findByUserId(Long userId);
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Transactional
    @Query("delete from UserSession us where us.user.id = :userId")
    void deleteByUserId(@Param("userId") Long userId);

    boolean existsByUserId(Long id);

    boolean existsBySessionId(String sessionId);
    void deleteBySessionId(String sessionId);

}
