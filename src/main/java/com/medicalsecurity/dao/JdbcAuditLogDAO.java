package com.medicalsecurity.dao;

import com.medicalsecurity.model.AuditEvent;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/** JDBC implementation of {@link AuditLogDAO}. */
public final class JdbcAuditLogDAO implements AuditLogDAO {

    private final Database database;

    public JdbcAuditLogDAO(Database database) {
        this.database = database;
    }

    @Override
    public void insert(final AuditEvent event) throws SQLException {
        database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "INSERT INTO audit_logs (event_type, username, user_id, transfer_id, outcome, "
                                + "detail, source_ip, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        Statement.RETURN_GENERATED_KEYS);
                try {
                    ps.setString(1, event.getEventType());
                    ps.setString(2, event.getUsername());
                    if (event.getUserId() != null) {
                        ps.setLong(3, event.getUserId().longValue());
                    } else {
                        ps.setNull(3, java.sql.Types.BIGINT);
                    }
                    ps.setString(4, event.getTransferId());
                    ps.setString(5, event.getOutcome());
                    ps.setString(6, event.getDetail());
                    ps.setString(7, event.getSourceIp());
                    ps.setTimestamp(8, new java.sql.Timestamp(
                            event.getCreatedAtMs() == 0 ? System.currentTimeMillis() : event.getCreatedAtMs()));
                    ps.executeUpdate();
                    return Integer.valueOf(1);
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<AuditEvent> findRecent(final int limit) throws SQLException {
        return (List<AuditEvent>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM audit_logs ORDER BY created_at DESC, id DESC");
                try {
                    return readLimited(ps, limit);
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<AuditEvent> findByTransferId(final String transferId) throws SQLException {
        return (List<AuditEvent>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM audit_logs WHERE transfer_id = ? ORDER BY created_at DESC, id DESC");
                try {
                    ps.setString(1, transferId);
                    return readLimited(ps, 500);
                } finally {
                    ps.close();
                }
            }
        });
    }

    @Override
    public List<AuditEvent> findByOutcome(final String outcome, final int limit) throws SQLException {
        return (List<AuditEvent>) database.withConnection(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                PreparedStatement ps = connection.prepareStatement(
                        "SELECT * FROM audit_logs WHERE outcome = ? ORDER BY created_at DESC, id DESC");
                try {
                    ps.setString(1, outcome);
                    return readLimited(ps, limit);
                } finally {
                    ps.close();
                }
            }
        });
    }

    private static List<AuditEvent> readLimited(PreparedStatement ps, int limit) throws SQLException {
        ResultSet rs = ps.executeQuery();
        try {
            List<AuditEvent> out = new ArrayList<AuditEvent>();
            while (rs.next() && out.size() < limit) {
                out.add(map(rs));
            }
            return out;
        } finally {
            rs.close();
        }
    }

    private static AuditEvent map(ResultSet rs) throws SQLException {
        AuditEvent e = new AuditEvent();
        e.setId(rs.getLong("id"));
        e.setEventType(rs.getString("event_type"));
        e.setUsername(rs.getString("username"));
        long userId = rs.getLong("user_id");
        e.setUserId(rs.wasNull() ? null : Long.valueOf(userId));
        e.setTransferId(rs.getString("transfer_id"));
        e.setOutcome(rs.getString("outcome"));
        e.setDetail(rs.getString("detail"));
        e.setSourceIp(rs.getString("source_ip"));
        java.sql.Timestamp created = rs.getTimestamp("created_at");
        e.setCreatedAtMs(created == null ? 0L : created.getTime());
        return e;
    }
}
