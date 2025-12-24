package com.auth.jwtsecurity.dto;

import lombok.Data;
import java.util.Set;

@Data
public class RoleAccessRequest {
    private String roleName;
    private Set<String> permissions;
}