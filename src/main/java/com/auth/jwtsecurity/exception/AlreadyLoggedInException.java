package com.auth.jwtsecurity.exception;

public class AlreadyLoggedInException extends RuntimeException {
    public AlreadyLoggedInException(String message) {
        super(message);
    }
}