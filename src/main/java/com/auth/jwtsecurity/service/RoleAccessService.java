package com.auth.jwtsecurity.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.auth.jwtsecurity.dto.RoleAccessRequest;
import com.auth.jwtsecurity.model.RoleAccess;
import com.auth.jwtsecurity.repository.RoleAccessRepository;

@Service
public class RoleAccessService {

    @Autowired
    private RoleAccessRepository repo;

    // Add new role
    public RoleAccess addRole(RoleAccessRequest req) {
        String roleName = req.getRoleName().toUpperCase();

        if (repo.findByRoleName(roleName).isPresent()) {
            throw new RuntimeException("Role already present");
        }

        RoleAccess role = new RoleAccess();
        role.setRoleName(roleName);
        role.setPermissions(req.getPermissions());
        return repo.save(role);
    }

    public List<RoleAccess> updateAll(List<RoleAccess> entity) {
        return repo.saveAll(entity);
    }

    public RoleAccess getAccess(String roleName) {
        return repo.findByRoleName(roleName.toUpperCase()).orElse(null);
    }

    public List<RoleAccess> getAllRoles() {
        return repo.findAll();
    }

    // ✅ SAFE PERMISSION CHECK
    public boolean hasPermission(String roleName, String permission) {
        return repo.findByRoleName(roleName.toUpperCase())
                .map(role ->
                        role.getPermissions()
                                .stream()
                                .anyMatch(p -> p.equalsIgnoreCase(permission))
                )
                .orElse(false);
    }

    // Update permissions ONLY (recommended)
    public RoleAccess updateRole(Long id, RoleAccessRequest req) {
        return repo.findById(id)
                .map(role -> {
                    role.setPermissions(req.getPermissions());
                    return repo.save(role);
                })
                .orElseThrow(() -> new RuntimeException("Role not found with id: " + id));
    }

    // Add new permissions (no duplicates)
    public RoleAccess addPermissions(String roleName, List<String> newPermissions) {
        return repo.findByRoleName(roleName.toUpperCase())
                .map(role -> {
                    newPermissions.forEach(p -> {
                        if (!role.getPermissions().contains(p.toUpperCase())) {
                            role.getPermissions().add(p.toUpperCase());
                        }
                    });
                    return repo.save(role);
                })
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
    }

    // Remove permission
    public RoleAccess removePermission(String roleName, String permission) {
        RoleAccess role = repo.findByRoleName(roleName.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        boolean removed = role.getPermissions()
                .removeIf(p -> p.equalsIgnoreCase(permission));

        if (!removed) {
            throw new RuntimeException("Permission not found: " + permission);
        }

        return repo.save(role);
    }

    // Delete role (ADMIN only – enforce via @PreAuthorize)
    public String deleteRole(String roleNameToDelete) {
        RoleAccess role = repo.findByRoleName(roleNameToDelete.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleNameToDelete));

        repo.delete(role);
        return "Role '" + roleNameToDelete.toUpperCase() + "' deleted successfully";
    }
}
