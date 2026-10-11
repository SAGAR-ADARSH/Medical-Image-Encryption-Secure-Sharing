package com.medicalsecurity.dao;

import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;
import com.medicalsecurity.support.TestSupport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * User persistence tests (spec section 11), executed against an in-memory
 * relational database using the project's real DAO layer.
 */
class UserDaoTest {

    private TestSupport.TestDb db;
    private JdbcUserDAO users;

    @BeforeEach
    void setUp() {
        db = TestSupport.newDatabase();
        users = new JdbcUserDAO(db.database);
    }

    @Test
    @DisplayName("Users are persisted with password hash and role")
    void createUserAndFind() throws Exception {
        final long id = users.insert("dr_test", "$pbkdf2-sha512$hash", "Dr Test", Role.DOCTOR, true);
        assertTrue(id > 0);
        final User found = users.findByUsername("dr_test");
        assertNotNull(found);
        assertEquals(Role.DOCTOR, found.getRole());
        assertEquals("Dr Test", found.getFullName());
        assertTrue(found.getPasswordHash() != null && found.getPasswordHash().length() > 0);
        assertTrue(users.findById(id) != null);
        assertNull(users.findByUsername("missing"));
    }

    @Test
    @DisplayName("Duplicate usernames are rejected")
    void duplicateUsernameRejected() throws Exception {
        users.insert("dr_dup", "$pbkdf2-sha512$hash", "A", Role.DOCTOR, true);
        assertThrows(DuplicateUserException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                users.insert("dr_dup", "$pbkdf2-sha512$hash2", "B", Role.SPECIALIST, true);
            }
        });
        assertTrue(users.existsUsername("dr_dup"));
        assertFalse(users.existsUsername("nobody"));
    }

    @Test
    @DisplayName("Active flag can be toggled and is persisted")
    void setActivePersists() throws Exception {
        final long id = users.insert("sp_toggle", "$pbkdf2-sha512$hash", "S", Role.SPECIALIST, true);
        assertTrue(users.findById(id).isActive());
        assertTrue(users.setActive(id, false));
        assertFalse(users.findById(id).isActive());
    }

    @Test
    @DisplayName("Listing users returns all accounts and filters by role")
    void listAllReturnsEveryone() throws Exception {
        users.insert("a_user", "$pbkdf2-sha512$h", "A", Role.ADMIN, true);
        users.insert("b_user", "$pbkdf2-sha512$h", "B", Role.DOCTOR, true);
        users.insert("c_user", "$pbkdf2-sha512$h", "C", Role.SPECIALIST, true);
        assertEquals(3, users.findAll().size());
        assertEquals(1, users.findByRole(Role.DOCTOR).size());
    }
}
