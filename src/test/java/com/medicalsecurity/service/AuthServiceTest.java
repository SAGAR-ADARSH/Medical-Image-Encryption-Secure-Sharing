package com.medicalsecurity.service;

import com.medicalsecurity.crypto.PasswordHasher;
import com.medicalsecurity.dao.JdbcAuditLogDAO;
import com.medicalsecurity.dao.JdbcUserDAO;
import com.medicalsecurity.model.AuditEvent;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.security.AuthenticationException;
import com.medicalsecurity.security.SessionManager;
import com.medicalsecurity.support.TestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Authentication service tests (spec section 11): login success/failure,
 * disabled accounts, session lifecycle and audit logging of auth events.
 */
class AuthServiceTest {

    private TestSupport.TestDb db;
    private JdbcUserDAO users;
    private PasswordHasher passwords;
    private JdbcAuditLogDAO auditDao;
    private AuditService audit;
    private AuthService auth;

    @BeforeEach
    void setUp() throws Exception {
        db = TestSupport.newDatabase();
        users = new JdbcUserDAO(db.database);
        passwords = new PasswordHasher();
        auditDao = new JdbcAuditLogDAO(db.database);
        audit = new AuditService(auditDao);
        auth = new AuthService(users, passwords, new SessionManager(), audit);
        final String hash = passwords.hash("Good-Passw0rd!".toCharArray());
        users.insert("dr_auth", hash, "Dr Auth", Role.DOCTOR, true);
        users.insert("sp_disabled", hash, "Sp Off", Role.SPECIALIST, false);
    }

    @Test
    @DisplayName("Login succeeds with the correct password and returns a session")
    void loginSucceeds() throws Exception {
        final UserSession session = auth.login("dr_auth", "Good-Passw0rd!".toCharArray(), "127.0.0.1");
        assertNotNull(session);
        assertNotNull(session.getToken());
        assertTrue(session.getToken().length() >= 16, "session tokens must be unpredictable");
        assertEquals("dr_auth", session.getUsername());
        assertEquals(Role.DOCTOR, session.getRole());
    }

    @Test
    @DisplayName("Login fails for wrong passwords and unknown users")
    void loginFailures() {
        assertThrows(AuthenticationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                auth.login("dr_auth", "wrong-password".toCharArray(), "127.0.0.1");
            }
        });
        assertThrows(AuthenticationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                auth.login("ghost", "Good-Passw0rd!".toCharArray(), "127.0.0.1");
            }
        });
    }

    @Test
    @DisplayName("Disabled accounts cannot log in")
    void disabledAccountsCannotLogIn() {
        assertThrows(AuthenticationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                auth.login("sp_disabled", "Good-Passw0rd!".toCharArray(), "127.0.0.1");
            }
        });
    }

    @Test
    @DisplayName("Authentication attempts are recorded in the audit log")
    void auditTrailRecordsAuthEvents() throws Exception {
        auth.login("dr_auth", "Good-Passw0rd!".toCharArray(), "127.0.0.1");
        try {
            auth.login("dr_auth", "wrong-password".toCharArray(), "127.0.0.1");
        } catch (AuthenticationException expected) {
            // expected
        }
        final List<AuditEvent> entries = auditDao.findRecent(50);
        final boolean sawOk = false;
        final boolean sawFail = false;
        for (int i = 0; i < entries.size(); i++) {
            AuditEvent e = (AuditEvent) entries.get(i);
            if (AuditEvent.AUTH_OK.equals(e.getEventType())) {
                sawOk = true;
            }
            if (AuditEvent.AUTH_FAIL.equals(e.getEventType())) {
                sawFail = true;
            }
        }
        assertTrue(sawOk, "AUTH_OK must be audited");
        assertTrue(sawFail, "AUTH_FAIL must be audited");
    }

    @Test
    @DisplayName("Session lookup works and logout invalidates the token")
    void sessionLifecycle() throws Exception {
        final UserSession session = auth.login("dr_auth", "Good-Passw0rd!".toCharArray(), "127.0.0.1");
        final UserSession validated = auth.validateSession(session.getToken());
        assertNotNull(validated);
        assertEquals("dr_auth", validated.getUsername());
        auth.logout(session.getToken(), "127.0.0.1");
        assertThrows(AuthenticationException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                auth.validateSession(session.getToken());
            }
        });
    }
}
