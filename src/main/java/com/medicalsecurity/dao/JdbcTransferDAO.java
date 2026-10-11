package com.medicalsecurity.dao;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferStatus;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;

/** JDBC implementation of {@link TransferDAO}. */
public final class JdbcTransferDAO implements TransferDAO {

    private final Database database;

    public JdbcTransferDAO(Database database) {
        this.database = database;
    }

    @Override
    public long insert(final ImageTransfer t) throws SQLException {
        return ((Long) database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                if (findByTransferId(connection, t.getTransferId()) != null) {
                    throw new SQLException("Duplicate transfer id (replay rejected): " + t.getTransferId(), "23505");
                }
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO image_transfers (transfer_id, sender_id, recipient_id, original_filename, "
                                + "content_type, plaintext_size, ciphertext_size, plaintext_sha256, algorithm, "
                                + "key_size_bits, nonce, tag_bits, status, storage_ref, error_detail, "
                                + "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);
                try {
                    Timestamp now = new Timestamp(System.currentTimeMillis());
                    ps.setString(1, t.getTransferId());
                    ps.setLong(2, t.getSenderId());
                    ps.setLong(3, t.getRecipientId());
                    ps.setString(4, t.getOriginalFilename());
                    ps.setString(5, t.getContentType());
                    ps.setLong(6, t.getPlaintextSize());
                    ps.setLong(7, t.getCiphertextSize());
                    ps.setString(8, t.getPlaintextSha256());
                    ps.setString(9, t.getAlgorithm());
                    ps.setInt(10, t.getKeySizeBits());
                    ps.setBytes(11, t.getNonce());
                    ps.setInt(12, t.getTagBits());
                    ps.setString(13, t.getStatus() == null ? TransferStatus.PENDING.name() : t.getStatus().name());
                    ps.setString(14, t.getStorageRef());
                    ps.setString(15, t.getErrorDetail());
                    ps.setTimestamp(16, now);
                    ps.setTimestamp(17, now);
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
    public ImageTransfer findByTransferId(final String transferId) throws SQLException {
        return (ImageTransfer) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                return findByTransferId(connection, transferId);
            }
        });
    }

    @Override
    public List<ImageTransfer> findByRecipientId(final long recipientId) throws SQLException {
        return (List<ImageTransfer>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM image_transfers WHERE recipient_id = ? ORDER BY created_at DESC");
                try {
                    ps.setLong(1, recipientId);
                    return mapAll(ps.executeQuery());
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<ImageTransfer> findBySenderId(final long senderId) throws SQLException {
        return (List<ImageTransfer>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM image_transfers WHERE sender_id = ? ORDER BY created_at DESC");
                try {
                    ps.setLong(1, senderId);
                    return mapAll(ps.executeQuery());
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<ImageTransfer> findRecent(final int limit) throws SQLException {
        return (List<ImageTransfer>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM image_transfers ORDER BY created_at DESC");
                try {
                    ResultSet rs = ps.executeQuery();
                    try {
                        List<ImageTransfer> out = new ArrayList<ImageTransfer>();
                        while (rs.next() && out.size() < limit) {
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
    public boolean updateStatus(final String transferId, final TransferStatus next,
                                final String errorDetail) throws SQLException {
        return ((Boolean) database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                ImageTransfer current = findByTransferId(connection, transferId);
                if (current == null) {
                    return Boolean.FALSE;
                }
                if (!current.getStatus().canTransitionTo(next)) {
                    throw new SQLException("Illegal status transition "
                            + current.getStatus() + " -> " + next + " for " + transferId, "22000");
                }
                PreparedStatement ps = connection.prepareStatement(
                        "UPDATE image_transfers SET status = ?, error_detail = ?, updated_at = ? "
                                + "WHERE transfer_id = ? AND status = ?");
                try {
                    Timestamp now = new Timestamp(System.currentTimeMillis());
                    ps.setString(1, next.name());
                    ps.setString(2, errorDetail);
                    ps.setTimestamp(3, now);
                    ps.setString(4, transferId);
                    ps.setString(5, current.getStatus().name());
                    boolean changed = ps.executeUpdate() == 1;
                    if (changed && next == TransferStatus.DECRYPTED) {
                        // completed_at stamped by markCompleted in the same flow
                    }
                    return Boolean.valueOf(changed);
                } finally {
                    ps.close();
                }
            }
        })).booleanValue();
    }

    @Override
    public boolean markReceived(final String transferId, final String storageRef,
                                final long ciphertextSize) throws SQLException {
        return ((Boolean) database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                ImageTransfer current = findByTransferId(connection, transferId);
                if (current == null) {
                    return Boolean.FALSE;
                }
                if (!current.getStatus().canTransitionTo(TransferStatus.RECEIVED)) {
                    throw new SQLException("Illegal status transition "
                            + current.getStatus() + " -> RECEIVED for " + transferId, "22000");
                }
                PreparedStatement ps = connection.prepareStatement(
                        "UPDATE image_transfers SET status = ?, storage_ref = ?, ciphertext_size = ?, "
                                + "received_at = ?, updated_at = ? WHERE transfer_id = ? AND status = ?");
                try {
                    Timestamp now = new Timestamp(System.currentTimeMillis());
                    ps.setString(1, TransferStatus.RECEIVED.name());
                    ps.setString(2, storageRef);
                    ps.setLong(3, ciphertextSize);
                    ps.setTimestamp(4, now);
                    ps.setTimestamp(5, now);
                    ps.setString(6, transferId);
                    ps.setString(7, current.getStatus().name());
                    return Boolean.valueOf(ps.executeUpdate() == 1);
                } finally {
                    ps.close();
                }
            }
        })).booleanValue();
    }

    @Override
    public boolean markCompleted(final String transferId) throws SQLException {
        return ((Boolean) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "UPDATE image_transfers SET completed_at = ?, updated_at = ? WHERE transfer_id = ?");
                try {
                    Timestamp now = new Timestamp(System.currentTimeMillis());
                    ps.setTimestamp(1, now);
                    ps.setTimestamp(2, now);
                    ps.setString(3, transferId);
                    return Boolean.valueOf(ps.executeUpdate() == 1);
                } finally {
                    ps.close();
                }
            }
        })).booleanValue();
    }

    private static ImageTransfer findByTransferId(Connection connection, String transferId)
            throws SQLException {
        PreparedStatement ps = connection.prepareStatement(
                "SELECT * FROM image_transfers WHERE transfer_id = ?");
        try {
            ps.setString(1, transferId);
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

    private static List<ImageTransfer> mapAll(ResultSet rs) throws SQLException {
        try {
            List<ImageTransfer> out = new ArrayList<ImageTransfer>();
            while (rs.next()) {
                out.add(map(rs));
            }
            return out;
        } finally {
            rs.close();
        }
    }

    private static ImageTransfer map(ResultSet rs) throws SQLException {
        ImageTransfer t = new ImageTransfer();
        t.setId(rs.getLong("id"));
        t.setTransferId(rs.getString("transfer_id"));
        t.setSenderId(rs.getLong("sender_id"));
        t.setRecipientId(rs.getLong("recipient_id"));
        t.setOriginalFilename(rs.getString("original_filename"));
        t.setContentType(rs.getString("content_type"));
        t.setPlaintextSize(rs.getLong("plaintext_size"));
        t.setCiphertextSize(rs.getLong("ciphertext_size"));
        t.setPlaintextSha256(rs.getString("plaintext_sha256"));
        t.setAlgorithm(rs.getString("algorithm"));
        t.setKeySizeBits(rs.getInt("key_size_bits"));
        t.setNonce(rs.getBytes("nonce"));
        t.setTagBits(rs.getInt("tag_bits"));
        t.setStatus(TransferStatus.fromString(rs.getString("status")));
        t.setStorageRef(rs.getString("storage_ref"));
        t.setErrorDetail(rs.getString("error_detail"));
        Timestamp created = rs.getTimestamp("created_at");
        Timestamp updated = rs.getTimestamp("updated_at");
        Timestamp received = rs.getTimestamp("received_at");
        Timestamp completed = rs.getTimestamp("completed_at");
        t.setCreatedAtMs(created == null ? 0L : created.getTime());
        t.setUpdatedAtMs(updated == null ? 0L : updated.getTime());
        t.setReceivedAtMs(received == null ? null : Long.valueOf(received.getTime()));
        t.setCompletedAtMs(completed == null ? null : Long.valueOf(completed.getTime()));
        return t;
    }
}
