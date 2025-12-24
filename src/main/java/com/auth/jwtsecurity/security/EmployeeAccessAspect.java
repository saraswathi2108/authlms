package com.auth.jwtsecurity.security;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.JoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.PathVariable;
import java.lang.annotation.Annotation;
import java.lang.reflect.Parameter;

@Aspect
@Component
@Slf4j
public class EmployeeAccessAspect {

    @Before("@annotation(checkAccess)")
    public void checkAccess(JoinPoint joinPoint, CheckEmployeeAccess checkAccess) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null) {
            throw new AccessDeniedException("Unauthorized: No authentication context found");
        }
        
        String targetEmployeeId = getEmployeeIdFromArgs(joinPoint, checkAccess.param());
        
        String currentEmployeeId = null;
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            currentEmployeeId = jwtAuth.getToken().getClaimAsString("employeeId");
            if (currentEmployeeId == null) {
                currentEmployeeId = jwtAuth.getToken().getSubject();
            }
        }
        boolean isSelf = targetEmployeeId != null && targetEmployeeId.equalsIgnoreCase(currentEmployeeId);
        //  Role-based check
        boolean hasRole = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(role -> {
                    for (String allowed : checkAccess.roles()) {
                        if (role.equals("ROLE_" + allowed)) return true;
                    }
                    return false;
                });

        if (!(isSelf || hasRole)) {
            log.warn(" Access denied: user={} attempted to modify employeeId={}", currentEmployeeId, targetEmployeeId);
            throw new AccessDeniedException("You don’t have permission to modify this employee");
        }
    }
    private String getEmployeeIdFromArgs(JoinPoint joinPoint, String paramName) {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Parameter[] parameters = signature.getMethod().getParameters();
        Object[] args = joinPoint.getArgs();

        for (int i = 0; i < parameters.length; i++) {
            for (Annotation annotation : parameters[i].getAnnotations()) {
                if (annotation instanceof PathVariable pathVar) {
                    String pathName = pathVar.value().isEmpty() ? parameters[i].getName() : pathVar.value();
                    if (pathName.equals(paramName)) {
                        return args[i].toString();
                    }
                }
            }
        }
        return null;
    }
}