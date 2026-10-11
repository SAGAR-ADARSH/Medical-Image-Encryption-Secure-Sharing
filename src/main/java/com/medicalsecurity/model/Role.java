package com.medicalsecurity.model;

import java.util.Locale;

/**
 * Application roles. Role permissions are enforced by the backend services
 * (see com.medicalsecurity.security.AuthorizationService); the UI only hides
 * controls as a convenience.
 */
public enum Role {
    ADMIN,
    DOCTOR,
    SPECIALIST;

    public static Role fromString(String value) {
        if (value == null) {
            throw new IllegalArgumentException("Role must not be null");
        }
        String v = value.trim().toUpperCase(Locale.ROOT);
        if ("ADMIN".equals(v)) {
            return ADMIN;
        }
        if ("DOCTOR".equals(v)) {
            return DOCTOR;
        }
        if ("SPECIALIST".equals(v)) {
            return SPECIALIST;
        }
        throw new IllegalArgumentException("Unknown role: " + value);
    }

    public boolean isAdmin() {
        return this == ADMIN;
    }

    public boolean canSendTransfers() {
        return this == DOCTOR || this == ADMIN;
    }

    public boolean canReceiveTransfers() {
        return this == SPECIALIST || this == ADMIN;
    }

    public boolean canManageUsers() {
        return this == ADMIN;
    }

    public boolean canViewAuditLog() {
        return this == ADMIN;
    }
}
