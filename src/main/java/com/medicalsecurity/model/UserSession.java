package com.medicalsecurity.model;

/**
 * Server-issued login session. The opaque token is the only credential that
 * crosses the socket protocol after authentication.
 */
public final class UserSession {

    private final String token;
    private final long userId;
    private final String username;
    private final Role role;
    private final long expiresAtMs;

    public UserSession(String token, long userId, String username, Role role, long expiresAtMs) {
        this.token = token;
        this.userId = userId;
        this.username = username;
        this.role = role;
        this.expiresAtMs = expiresAtMs;
    }

    public String getToken() {
        return token;
    }

    public long getUserId() {
        return userId;
    }

    public String getUsername() {
        return username;
    }

    public Role getRole() {
        return role;
    }

    public long getExpiresAtMs() {
        return expiresAtMs;
    }

    public boolean isExpired(long nowMs) {
        return nowMs > expiresAtMs;
    }
}
