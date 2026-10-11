package com.medicalsecurity.service;

import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.UserDAO;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.User;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.security.AuthenticationException;
import com.medicalsecurity.security.SessionManager;

/**
 * Authentication: verifies username/password against the stored salted hash,
 * rejects deactivated accounts, issues sessions and writes auth audit events.
 * Error messages do not reveal whether the username exists.
 */
public final class AuthService {

    private static final String GENERIC_FAILURE = "Invalid username or password";

    private final UserDAO userDAO;
    private final PasswordHasher passwordHasher;
    private final SessionManager sessionManager;
    private final AuditService audit;

    public AuthService(UserDAO userDAO, PasswordHasher passwordHasher,
                       SessionManager sessionManager, AuditService audit) {
        this.userDAO = userDAO;
        this.passwordHasher = passwordHasher;
        this.sessionManager = sessionManager;
        this.audit = audit;
    }

    public UserSession login(String username, char[] password, String sourceIp) {
        String safeUser = username == null ? "" : username.trim();
        try {
            User user = userDAO.findByUsername(safeUser);
            if (user == null || user.getPasswordHash() == null) {
                audit.failure(AuditEvent.AUTH_FAIL, safeUser, null, null, "Unknown user", sourceIp);
                throw new AuthenticationException(GENERIC_FAILURE);
            }
            if (!user.isActive()) {
                audit.denied(AuditEvent.AUTH_FAIL, safeUser, Long.valueOf(user.getId()), null,
                        "Account deactivated", sourceIp);
                throw new AuthenticationException("Account is deactivated. Contact an administrator.");
            }
            if (!passwordHasher.verify(password, user.getPasswordHash())) {
                audit.failure(AuditEvent.AUTH_FAIL, safeUser, Long.valueOf(user.getId()), null,
                        "Bad password", sourceIp);
                throw new AuthenticationException(GENERIC_FAILURE);
            }
            UserSession session = sessionManager.create(user.getId(), user.getUsername(), user.getRole());
            audit.success(AuditEvent.AUTH_OK, user.getUsername(), Long.valueOf(user.getId()), null,
                    "Login", sourceIp);
            return session;
        } catch (AuthenticationException e) {
            throw e;
        } catch (Exception e) {
            // Never leak storage errors or stack traces to the caller.
            audit.failure(AuditEvent.AUTH_FAIL, safeUser, null, null, "Login error", sourceIp);
            throw new AuthenticationException(GENERIC_FAILURE);
        }
    }

    public UserSession validateSession(String token) {
        return sessionManager.validate(token);
    }

    public void logout(String token, String sourceIp) {
        UserSession session = null;
        try {
            session = sessionManager.validate(token);
        } catch (AuthenticationException ignored) {
            // already invalid
        }
        sessionManager.revoke(token);
        if (session != null) {
            audit.success(AuditEvent.AUTH_OK, session.getUsername(), Long.valueOf(session.getUserId()),
                    null, "Logout", sourceIp);
        }
    }

    /** Resolves the full user record for a session (freshness of role/active flags). */
    public User requireFreshUser(UserSession session) {
        User user;
        try {
            user = userDAO.findById(session.getUserId());
        } catch (Exception e) {
            throw new AuthenticationException("User lookup failed");
        }
        if (user == null || !user.isActive()) {
            throw new AuthenticationException("Account is no longer active");
        }
        return user;
    }

    public PasswordHasher getPasswordHasher() {
        return passwordHasher;
    }

    /** Convenience for account creation paths (wipe the array when done). */
    public static char[] toCharArray(String value) {
        return value == null ? new char[0] : value.toCharArray();
    }
}
