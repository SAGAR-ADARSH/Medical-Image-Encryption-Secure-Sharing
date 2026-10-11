package com.medicalsecurity.dao;

import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/** JDBC implementation of {@link UserDAO} (portable across MySQL and Derby). */
public final class JdbcUserDAO implements UserDAO {

    private final Database database;

    public JdbcUserDAO(Database database) {
        this.database = database;
    }

    @Override
    public long insert(final String username, final String passwordHash, final String fullName,
                       final Role role, final boolean active) throws SQLException {
        try {
            return ((Long) database.inTransaction(new Database.DbWork() {
                @Override
                public Object run(Connection connection) throws SQLException {
                    if (existsUsername(connection, username)) {
                        throw new DuplicateUserException("Username already exists: " + username);
                    }
                    PreparedStatement ps = connection.prepareStatement(
                            "INSERT INTO users (username, password_hash, full_name, role, active, created_at, updated_at) "
                                    + "VALUES (?, ?, ?, ?, ?, ?, ?)",
                            Statement.RETURN_GENERATED_KEYS);
                    try {
                        Timestamp now = new Timestamp(System.currentTimeMillis());
                        ps.setString(1, username);
                        ps.setString(2, passwordHash);
                        ps.setString(3, fullName);
                        ps.setString(4, role.name());
                        ps.setInt(5, active ? 1 : 0);
                        ps.setTimestamp(6, now);
                        ps.setTimestamp(7, now);
                        ps.executeUpdate();
                        ResultSet keys = ps.getGeneratedKeys();
                        try {
                            if (keys.next()) {
                                return Long.valueOf(keys.getLong(1));
                            }
                        } finally {
                            keys.close();
                        }
                        throw new SQLException("Insert did not return a generated id");
                    } finally {
                        ps.close();
                    }
                }
            })).longValue();
        } catch (SQLException e) {
            // Belt-and-braces: some drivers only surface the unique violation here.
            if (isUniqueViolation(e)) {
                throw new DuplicateUserException("Username already exists: " + username, e);
            }
            throw e;
        }
    }

    private static boolean isUniqueViolation(SQLException e) {
        String state = e.getSQLState();
        // 23xxx = integrity constraint violation on both MySQL and Derby.
        return state != null && state.startsWith("23");
    }

    @Override
    public User findByUsername(final String username) throws SQLException {
        return (User) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT id, username, password_hash, full_name, role, active, created_at FROM users WHERE username = ?");
                try {
                    ps.setString(1, username);
                    ResultSet rs = ps.executeQuery();
                    try {
                        return rs.next() ? map(rs) : null;
                    } finally {
                        rs.close();
                    }
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public User findById(final long id) throws SQLException {
        return (User) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT id, username, password_hash, full_name, role, active, created_at FROM users WHERE id = ?");
                try {
                    ps.setLong(1, id);
                    ResultSet rs = ps.executeQuery();
                    try {
                        return rs.next() ? map(rs) : null;
                    } finally {
                        rs.close();
                    }
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<User> findAll() throws SQLException {
        return (List<User>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT id, username, password_hash, full_name, role, active, created_at FROM users ORDER BY id");
                try {
                    ResultSet rs = ps.executeQuery();
                    try {
                        List<User> out = new ArrayList<User>();
                        while (rs.next()) {
                            out.add(map(rs));
                        }
                        return out;
                    } finally {
                        rs.close();
                    }
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<User> findByRole(final Role role) throws SQLException {
        return (List<User>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT id, username, password_hash, full_name, role, active, created_at FROM users WHERE role = ? ORDER BY id");
                try {
                    ps.setString(1, role.name());
                    ResultSet rs = ps.executeQuery();
                    try {
                        List<User> out = new ArrayList<User>();
                        while (rs.next()) {
                            out.add(map(rs));
                        }
                        return out;
                    } finally {
                        rs.close();
                    }
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public boolean setActive(final long userId, final boolean active) throws SQLException {
        return ((Boolean) database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "UPDATE users SET active = ?, updated_at = ? WHERE id = ?");
                try {
                    ps.setInt(1, active ? 1 : 0);
                    ps.setTimestamp(2, new Timestamp(System.currentTimeMillis()));
                    ps.setLong(3, userId);
                    return Boolean.valueOf(ps.executeUpdate() == 1);
                } finally {
                    ps.close();
                }
            }
        })).booleanValue();
    }

    @Override
    public boolean existsUsername(final String username) throws SQLException {
        return ((Boolean) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                return Boolean.valueOf(existsUsername(connection, username));
            }
        })).booleanValue();
    }

    private static boolean existsUsername(Connection connection, String username) throws SQLException {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT 1 FROM users WHERE username = ?");
        try {
            ps.setString(1, username);
            ResultSet rs = ps.executeQuery();
            try {
                return rs.next();
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
    }

    private static User map(ResultSet rs) throws SQLException {
        long id = rs.getLong("id");
        String username = rs.getString("username");
        String passwordHash = rs.getString("password_hash");
        String fullName = rs.getString("full_name");
        Role role = Role.fromString(rs.getString("role"));
        boolean active = rs.getInt("active") == 1;
        Timestamp created = rs.getTimestamp("created_at");
        long createdMs = created == null ? 0L : created.getTime();
        return new User(id, username, fullName, role, active, createdMs, passwordHash);
    }
}
