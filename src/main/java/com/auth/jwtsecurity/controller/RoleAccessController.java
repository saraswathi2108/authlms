package com.auth.jwtsecurity.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
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
@RequestMapping("api/auth/role-access")
public class RoleAccessController {

    @Autowired
    private RoleAccessService service;

    @GetMapping("/all")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public List<RoleAccess> getAll() {
        return service.getAllRoles();
    }

    @PostMapping("/updateAll")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public List<RoleAccess> upDateAll(@RequestBody List<RoleAccess> entity) {
        return service.updateAll(entity);
    }
    
    // Get role by name
    @GetMapping("/{role}")
    // @CheckPermission(value = "PERMISSIONS_BUTTONS")
    public RoleAccess getRoleAccess(@PathVariable String role) {
        System.out.println("Role: " + role);
        return service.getAccess(role);
    }

    // Check if role has specific permission
    @GetMapping("/{role}/check/{permission}")
    public boolean checkPermission(@PathVariable String role, @PathVariable String permission) {
        return service.hasPermission(role, permission);
    }

    // Add new role
    @PostMapping
//     @CheckPermission("PERMISSIONS_BUTTONS")
    public RoleAccess addRole(@RequestBody RoleAccessRequest req) {
        return service.addRole(req);
    }
    
 // ✅ Get all roles and their permissions
    @GetMapping
//    @CheckPermission(value = "PERMISSIONS_BUTTONS")
    public List<RoleAccess> getAllRoles() {
        return service.getAllRoles();
    }


    // Update role completely (rename + overwrite permissions)
    @PutMapping("/{id}")
//   @CheckPermission("PERMISSIONS_BUTTONS")
    public RoleAccess updateRole(@PathVariable Long id, @RequestBody RoleAccessRequest req) {
        return service.updateRole(id, req);
    }

    // Add new permissions to an existing role
    @PatchMapping("/{role}/permissions")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public RoleAccess addPermissions(@PathVariable String role, @RequestBody List<String> newPermissions) {
        return service.addPermissions(role, newPermissions);
    }
    
 // ✅ Remove a permission from a role
    @DeleteMapping("/{role}/permission/{permission}")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public RoleAccess removePermission(
            @PathVariable String role,
            @PathVariable String permission) {
        return service.removePermission(role.toUpperCase(), permission.toUpperCase());
    }

    @DeleteMapping("/delete/{callerRole}/{roleToDelete}")
//    @CheckPermission("PERMISSIONS_BUTTONS")
    public String deleteRole(
            @PathVariable String callerRole,
            @PathVariable String roleToDelete) {
        return service.deleteRole(callerRole.toUpperCase(), roleToDelete.toUpperCase());
    }                                                                                     

}
