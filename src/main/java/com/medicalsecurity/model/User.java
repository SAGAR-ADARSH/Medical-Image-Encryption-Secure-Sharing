package com.medicalsecurity.model;

/**
 * Immutable user account. {@code passwordHash} is server-side state: it is
 * never written to socket protocol messages, logs or UI views.
 */
public final class User {

    private final long id;
    private final String username;
    private final String fullName;
    private final Role role;
    private final boolean active;
    private final long createdAtMs;
    private final String passwordHash;

    public User(long id, String username, String fullName, Role role,
                boolean active, long createdAtMs, String passwordHash) {
        this.id = id;
        this.username = username;
        this.fullName = fullName;
        this.role = role;
        this.active = active;
        this.createdAtMs = createdAtMs;
        this.passwordHash = passwordHash;
    }

    public long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getFullName() {
        return fullName;
    }

    public Role getRole() {
        return role;
    }

    public boolean isActive() {
        return active;
    }

    public long getCreatedAtMs() {
        return createdAtMs;
    }

    /** Server-side only. Never serialize this to clients. */
    public String getPasswordHash() {
        return passwordHash;
    }

    /** Copy without credential material, safe for protocol responses. */
    public User withoutCredentials() {
        return new User(id, username, fullName, role, active, createdAtMs, null);
    }

    @Override
    public String toString() {
        return username + " (" + role + ")";
    }
}
