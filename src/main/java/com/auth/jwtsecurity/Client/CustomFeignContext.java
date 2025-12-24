package com.auth.jwtsecurity.Client;
import org.springframework.stereotype.Component;

@Component
public class CustomFeignContext {
    private static final ThreadLocal<String> TOKEN = new ThreadLocal<>();

    public void setToken(String token) {
        TOKEN.set(token);
    }

    public String getToken() {
        return TOKEN.get();
    }

    public void clear() {
        TOKEN.remove();
    }
}
