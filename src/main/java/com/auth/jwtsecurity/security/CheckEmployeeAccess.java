package com.auth.jwtsecurity.security;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD})  // <-- put inside { }
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface CheckEmployeeAccess {
    String param() default "employeeId";   // PathVariable name
    String[] roles() default {};           // Allowed roles
}
