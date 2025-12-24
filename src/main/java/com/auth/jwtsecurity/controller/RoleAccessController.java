package com.auth.jwtsecurity.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.jwtsecurity.dto.RoleAccessRequest;
import com.auth.jwtsecurity.model.RoleAccess;
import com.auth.jwtsecurity.security.CheckEmployeeAccess;
//import com.auth.jwtsecurity.security.CheckPermission;
import com.auth.jwtsecurity.service.RoleAccessService;

@RestController
@RequestMapping("/api/auth/role-access")
public class RoleAccessController {

    @Autowired
    private RoleAccessService service;

    // ================= READ =================

    // Get all roles
    @GetMapping
    public List<RoleAccess> getAllRoles() {
        return service.getAllRoles();
    }

    // Get role by name
    @GetMapping("/{role}")
    public RoleAccess getRoleAccess(@PathVariable String role) {
        return service.getAccess(role);
    }

    // Check if role has specific permission
    @GetMapping("/{role}/check/{permission}")
    public boolean checkPermission(
            @PathVariable String role,
            @PathVariable String permission) {
        return service.hasPermission(role, permission);
    }

    // ================= ADMIN ONLY =================

    // Add new role
    @PostMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public RoleAccess addRole(@RequestBody RoleAccessRequest req) {
        return service.addRole(req);
    }

    // Update role permissions (NO rename)
    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public RoleAccess updateRole(
            @PathVariable Long id,
            @RequestBody RoleAccessRequest req) {
        return service.updateRole(id, req);
    }

    // Add permissions to a role
    @PatchMapping("/{role}/permissions")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public RoleAccess addPermissions(
            @PathVariable String role,
            @RequestBody List<String> newPermissions) {
        return service.addPermissions(role, newPermissions);
    }

    // Remove a permission
    @DeleteMapping("/{role}/permission/{permission}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public RoleAccess removePermission(
            @PathVariable String role,
            @PathVariable String permission) {
        return service.removePermission(role, permission);
    }

    // Delete role
    @DeleteMapping("/{role}")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String deleteRole(@PathVariable String role) {
        return service.deleteRole(role);
    }
}
