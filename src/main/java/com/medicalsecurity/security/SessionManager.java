package com.medicalsecurity.security;

import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.util.SecureIds;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Server-side session registry. After a successful login the server issues an
 * opaque random token; every later socket command must present it. Tokens
 * expire after {@link #SESSION_TTL_MS}.
 */
public final class SessionManager {

    public static final long SESSION_TTL_MS = 8L * 60L * 60L * 1000L; // 8 hours

    private final Map<String, UserSession> sessions = new ConcurrentHashMap<String, UserSession>();

    public UserSession create(long userId, String username,
                              com.medicalsecurity.model.Role role) {
        long now = System.currentTimeMillis();
        UserSession session = new UserSession(
                SecureIds.newSessionToken(), userId, username, role, now + SESSION_TTL_MS);
        sessions.put(session.getToken(), session);
        return session;
    }

    /**
     * Validates a token and returns the session; throws when missing/expired
     * (expired sessions are pruned lazily).
     */
    public UserSession validate(String token) {
        if (token == null || token.isEmpty()) {
            throw new AuthenticationException("Not authenticated");
        }
        long now = System.currentTimeMillis();
        UserSession session = (UserSession) sessions.get(token);
        if (session == null) {
            throw new AuthenticationException("Invalid or expired session");
        }
        if (session.isExpired(now)) {
            sessions.remove(token);
            throw new AuthenticationException("Session expired, please log in again");
        }
        return session;
    }

    public void revoke(String token) {
        if (token != null) {
            sessions.remove(token);
        }
    }

    /** Drops all expired sessions (housekeeping). */
    public void pruneExpired() {
        long now = System.currentTimeMillis();
        Iterator<?> it = sessions.entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry<?, ?> entry = (Map.Entry<?, ?>) it.next();
            UserSession session = (UserSession) entry.getValue();
            if (session.isExpired(now)) {
                it.remove();
            }
        }
    }

    public int activeCount() {
        return sessions.size();
    }
}
