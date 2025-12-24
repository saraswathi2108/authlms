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
        RoleAccess role = new RoleAccess();
        if (repo.findByRoleName(req.getRoleName()).isPresent()) throw new RuntimeException("Role already present");
        role.setRoleName(req.getRoleName().toUpperCase());
        role.setPermissions(req.getPermissions());
        return repo.save(role);
    }

    public List<RoleAccess> updateAll(List<RoleAccess> entity) {
        return repo.saveAll(entity);
    }

    // Get role access
    public RoleAccess getAccess(String roleName) {
        System.out.println(roleName);
        return repo.findByRoleName(roleName.toUpperCase()).orElse(null);
    }

    public List<RoleAccess> getAllRoles() {
        return repo.findAll();
    }

    // Check if role has permission
    public boolean hasPermission(String roleName, String permission) {
        System.out.println("Role: " + roleName + ", Permission: " + permission);
        System.out.println(repo.findByRoleName(roleName.toUpperCase()));
        RoleAccess role = repo.findByRoleName(roleName.toUpperCase()).orElse(null);
        if(role.getPermissions().stream().anyMatch(p -> p.equalsIgnoreCase(permission))){
            return true;
        }
        else return false;
    }

    // Update role (name + permissions)
    public RoleAccess updateRole(Long id, RoleAccessRequest req) {
        return repo.findById(id).map(role -> {
            role.setRoleName(req.getRoleName().toUpperCase());
            role.setPermissions(req.getPermissions());
            return repo.save(role);
        }).orElseThrow(() -> new RuntimeException("Role not found with id: " + id));
    }

    // Add new permissions to existing role
    public RoleAccess addPermissions(String roleName, List<String> newPermissions) {
        return repo.findByRoleName(roleName.toUpperCase())
                .map(role -> {
                    role.getPermissions().addAll(newPermissions);
                    return repo.save(role);
                }).orElseThrow(() -> new RuntimeException("Role not found: " + roleName));
    }

    // Remove a permission (case-insensitive)
    public RoleAccess removePermission(String roleName, String permission) {
        RoleAccess role = repo.findByRoleName(roleName.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleName));

        boolean removed = role.getPermissions()
                .removeIf(p -> p.equalsIgnoreCase(permission));

        if (!removed) {
            throw new RuntimeException("Permission not found: " + permission);
        }

        return repo.save(role); // save updated permissions
    }
    
    public String deleteRole(String callerRole, String roleNameToDelete) {
        if (!"ADMIN".equalsIgnoreCase(callerRole)) {
            throw new RuntimeException("Only ADMIN can delete roles");
        }

        RoleAccess role = repo.findByRoleName(roleNameToDelete.toUpperCase())
                .orElseThrow(() -> new RuntimeException("Role not found: " + roleNameToDelete));

        repo.delete(role);
        return "Role '" + roleNameToDelete.toUpperCase() + "' deleted successfully by ADMIN";
    }
    
 // Get all roles with permissions
}
