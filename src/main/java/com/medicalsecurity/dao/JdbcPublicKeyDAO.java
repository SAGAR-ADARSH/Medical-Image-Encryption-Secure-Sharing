package com.medicalsecurity.dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/** JDBC implementation of {@link PublicKeyDAO}. */
public final class JdbcPublicKeyDAO implements PublicKeyDAO {

    private final Database database;

    public JdbcPublicKeyDAO(Database database) {
        this.database = database;
    }

    @Override
    public long insert(final long userId, final String algorithm, final int keySizeBits,
                       final byte[] publicKeyDer, final int keyVersion, final String keystoreRef)
            throws SQLException {
        return ((Long) database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO user_public_keys (user_id, algorithm, key_size_bits, public_key, "
                                + "key_version, keystore_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);
                try {
                    ps.setLong(1, userId);
                    ps.setString(2, algorithm);
                    ps.setInt(3, keySizeBits);
                    ps.setBytes(4, publicKeyDer);
                    ps.setInt(5, keyVersion);
                    ps.setString(6, keystoreRef);
                    ps.setTimestamp(7, new java.sql.Timestamp(System.currentTimeMillis()));
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
    }

    @Override
    public PublicKeyRecord findLatestByUserId(final long userId) throws SQLException {
        return (PublicKeyRecord) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT p.id, p.user_id, u.username, p.algorithm, p.key_size_bits, p.public_key, p.key_version "
                                + "FROM user_public_keys p JOIN users u ON u.id = p.user_id "
                                + "WHERE p.user_id = ? ORDER BY p.key_version DESC");
                try {
                    ps.setLong(1, userId);
                    return first(ps);
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public PublicKeyRecord findLatestByUsername(final String username) throws SQLException {
        return (PublicKeyRecord) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT p.id, p.user_id, u.username, p.algorithm, p.key_size_bits, p.public_key, p.key_version "
                                + "FROM user_public_keys p JOIN users u ON u.id = p.user_id "
                                + "WHERE u.username = ? ORDER BY p.key_version DESC");
                try {
                    ps.setString(1, username);
                    return first(ps);
                } finally {
                    ps.close();
                }
            }
        });
    }

    private static PublicKeyRecord first(PreparedStatement ps) throws SQLException {
        ResultSet rs = ps.executeQuery();
        try {
            if (!rs.next()) {
                return null;
            }
            return new PublicKeyRecord(
                    rs.getLong("id"),
                    rs.getLong("user_id"),
                    rs.getString("username"),
                    rs.getString("algorithm"),
                    rs.getInt("key_size_bits"),
                    rs.getBytes("public_key"),
                    rs.getInt("key_version"));
        } finally {
            rs.close();
        }
    }
}
