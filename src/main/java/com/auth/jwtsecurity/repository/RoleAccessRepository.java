package com.auth.jwtsecurity.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.auth.jwtsecurity.model.RoleAccess;

public interface RoleAccessRepository extends JpaRepository<RoleAccess, Long> {

    // RoleAccess findByRoleName(String upperCase);
    Optional<RoleAccess> findByRoleName(String roleName);
}
