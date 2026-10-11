package com.medicalsecurity.dao;

import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;

import java.sql.SQLException;
import java.util.List;

/**
 * User-account persistence. Duplicate usernames are rejected by the database
 * unique constraint AND by an explicit existence check.
 */
public interface UserDAO {

    /**
     * Creates an account and returns its generated id.
     *
     * @throws DuplicateUserException when the username already exists
     */
    long insert(String username, String passwordHash, String fullName, Role role, boolean active)
            throws SQLException;

    User findByUsername(String username) throws SQLException;

    User findById(long id) throws SQLException;

    List<User> findAll() throws SQLException;

    List<User> findByRole(Role role) throws SQLException;

    boolean setActive(long userId, boolean active) throws SQLException;

    boolean existsUsername(String username) throws SQLException;
}
