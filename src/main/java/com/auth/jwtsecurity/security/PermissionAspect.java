//package com.auth.jwtsecurity.security;
//
//import java.util.*;
//import java.util.stream.Collectors;
//
//import org.aspectj.lang.JoinPoint;
//import org.aspectj.lang.annotation.Aspect;
//import org.aspectj.lang.annotation.Before;
//import org.springframework.security.access.AccessDeniedException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.context.SecurityContextHolder;
//import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
//import org.springframework.stereotype.Component;
//import org.springframework.web.context.request.RequestContextHolder;
//import org.springframework.web.context.request.ServletRequestAttributes;
//import org.springframework.web.servlet.HandlerMapping;
//
//import com.auth.jwtsecurity.service.RoleAccessService;
//
//import io.jsonwebtoken.Jwt;
//import jakarta.servlet.http.HttpServletRequest;
//import lombok.RequiredArgsConstructor;
//import lombok.extern.slf4j.Slf4j;
//
//@Aspect
//@Component
//@Slf4j
//@RequiredArgsConstructor
//public class PermissionAspect {
//
//    private final RoleAccessService roleAccessService;
//
//    @Before("@annotation(checkPermission)")
//    public void checkPermission(JoinPoint joinPoint, CheckPermission checkPermission) {
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//
//        if (auth == null) {
//            throw new AccessDeniedException("Unauthorized: No authentication context found");
//        }
//
//
//        Set<String> userRoles = auth.getAuthorities().stream()
//                .map(GrantedAuthority::getAuthority)
//                .collect(Collectors.toSet());
//
//        String permission = checkPermission.value();
//
//
//        boolean hasAccess = userRoles.stream()
//                .anyMatch(role -> roleAccessService.hasPermission(role, permission));
//
//        if (!hasAccess) {
//            log.warn("❌ Access denied: roles={} attempted permission={}", userRoles, permission);
//            throw new AccessDeniedException("You don’t have permission to perform this action: " + permission);
//        }
//        log.info("✅ Access granted: roles={} attempted permission={}", userRoles, permission);
//
//        Set<String> restrictedRoles = new HashSet<>(Arrays.asList(checkPermission.MatchParmForRoles()));
//        boolean userHasRestrictedRole = userRoles.stream().anyMatch(restrictedRoles::contains);
//
//        if (userHasRestrictedRole
//                && !checkPermission.MatchParmName().isEmpty()
//                && !checkPermission.MatchParmFromUrl().isEmpty()) {
//
//            log.info("Checking claim {} against URL parameter {}", checkPermission.MatchParmName(), checkPermission.MatchParmFromUrl());
//
//            String claimValue = null;
//            if (auth instanceof JwtAuthenticationToken jwtAuth) {
//                log.info("Claim value reached into instanceOf: {}", jwtAuth.getToken().getClaimAsString(checkPermission.MatchParmName()));
//                claimValue = jwtAuth.getToken().getClaimAsString(checkPermission.MatchParmName());
//                if (claimValue == null) {
//                    claimValue = jwtAuth.getToken().getSubject();
//                }
//            }
//            ServletRequestAttributes requestAttributes =
//                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
//            // log.info("Request attributes: {}", requestAttributes);
//            if (requestAttributes != null) {
//                HttpServletRequest request = requestAttributes.getRequest();
//                Map<String, String> pathVariables =
//                        (Map<String, String>) request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
//                String urlValue = pathVariables.get(checkPermission.MatchParmFromUrl());
//                log.info("URL parameter value: {} ans claim value: {}", urlValue, claimValue);
//                if (urlValue != null && !urlValue.equalsIgnoreCase(claimValue)) {
//                    throw new AccessDeniedException(
//                            String.format("Access denied: Claim %s (%s) does not match URL parameter %s (%s)",
//                                    checkPermission.MatchParmName(), claimValue,
//                                    checkPermission.MatchParmFromUrl(), urlValue)
//                    );
//                }
//            } else {
//                throw new AccessDeniedException(
//
//                        String.format("Access denied: Claim %s does not match URL parameter %s",
//                                checkPermission.MatchParmName(), checkPermission.MatchParmFromUrl())
//                );
//            }
//        }
//    }
//}
