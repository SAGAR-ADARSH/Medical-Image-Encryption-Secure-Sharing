package com.medicalsecurity.dao;

import com.medicalsecurity.model.ProtectedKeyMaterial;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

/** JDBC implementation of {@link KeyRecordDAO}. */
public final class JdbcKeyRecordDAO implements KeyRecordDAO {

    private final Database database;

    public JdbcKeyRecordDAO(Database database) {
        this.database = database;
    }

    @Override
    public void insert(final ProtectedKeyMaterial material) throws SQLException {
        database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                if (findByTransferId(connection, material.getTransferId()) != null) {
                    throw new SQLException("Protected key material already stored for "
                            + material.getTransferId(), "23505");
                }
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO protected_key_material (transfer_id, wrap_algorithm, wrapped_key, "
                                + "recipient_key_id, key_version, created_at) VALUES (?, ?, ?, ?, ?, ?)");
                try {
                    ps.setString(1, material.getTransferId());
                    ps.setString(2, material.getWrapAlgorithm());
                    ps.setBytes(3, material.getWrappedKey());
                    if (material.getRecipientKeyId() > 0) {
                        ps.setLong(4, material.getRecipientKeyId());
                    } else {
                        ps.setNull(4, java.sql.Types.BIGINT);
                    }
                    ps.setInt(5, material.getKeyVersion());
                    ps.setTimestamp(6, new java.sql.Timestamp(System.currentTimeMillis()));
                    ps.executeUpdate();
                    return Integer.valueOf(1);
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public ProtectedKeyMaterial findByTransferId(final String transferId) throws SQLException {
        return (ProtectedKeyMaterial) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                return findByTransferId(connection, transferId);
            }
        });
    }

    private static ProtectedKeyMaterial findByTransferId(Connection connection, String transferId)
            throws SQLException {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT k.transfer_id, k.wrap_algorithm, k.wrapped_key, k.key_version, k.recipient_key_id, "
                        + "u.username AS recipient_username "
                        + "FROM protected_key_material k "
                        + "LEFT JOIN user_public_keys p ON p.id = k.recipient_key_id "
                        + "LEFT JOIN users u ON u.id = p.user_id "
                        + "WHERE k.transfer_id = ?");
        try {
            ps.setString(1, transferId);
            ResultSet rs = ps.executeQuery();
            try {
                if (!rs.next()) {
                    return null;
                }
                String recipientUsername = rs.getString("recipient_username");
                long keyId = rs.getLong("recipient_key_id");
                boolean keyIdNull = rs.wasNull();
                return new ProtectedKeyMaterial(
                        rs.getString("transfer_id"),
                        rs.getString("wrap_algorithm"),
                        rs.getBytes("wrapped_key"),
                        recipientUsername,
                        keyIdNull ? 0L : keyId,
                        rs.getInt("key_version"));
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
    }
}
