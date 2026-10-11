package com.medicalsecurity.dao;

import com.medicalsecurity.config.AppConfig;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * JDBC connection management. Uses {@link DriverManager} with the configured
 * driver/URL and enforces two rules everywhere:
 * <ul>
 *   <li>every connection is closed (try/finally),</li>
 *   <li>multi-statement state changes run inside a transaction.</li>
 * </ul>
 * Works with MySQL Connector/J and with the embedded Derby driver used by the
 * automated tests - all SQL is written in a portable subset.
 */
public final class Database {

    /** Work executed with a borrowed connection. */
    public abstract static class DbWork {
        public abstract Object run(Connection connection) throws SQLException;
    }

    private final String driverClass;
    private final String url;
    private final String user;
    private final String password;

    public Database(String driverClass, String url, String user, String password) {
        this.driverClass = driverClass;
        this.url = url;
        this.user = user;
        this.password = password == null ? "" : password;
        loadDriver();
    }

    public static Database fromConfig(AppConfig config) {
        return new Database(config.getDbDriver(), config.getDbUrl(),
                config.getDbUser(), config.getDbPassword());
    }

    private void loadDriver() {
        try {
            Class.forName(driverClass);
        } catch (ClassNotFoundException e) {
            // Some drivers (e.g. Derby 10.16) register themselves through the
            // service loader; verify DriverManager can serve the URL instead.
            try {
                DriverManager.getDriver(url);
            } catch (SQLException e2) {
                throw new IllegalStateException(
                        "JDBC driver not on the classpath: " + driverClass
                                + " (check the Maven dependencies / DB_DRIVER setting)", e);
            }
        }
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection(url, user, password);
    }

    /** Runs work with a connection that is always closed afterwards. */
    public Object withConnection(DbWork work) throws SQLException {
        Connection connection = getConnection();
        try {
            return work.run(connection);
        } finally {
            closeQuietly(connection);
        }
    }

    /** Runs work in a single transaction: commit on success, rollback on error. */
    public Object inTransaction(DbWork work) throws SQLException {
        Connection connection = getConnection();
        try {
            connection.setAutoCommit(false);
            Object result;
            try {
                result = work.run(connection);
                connection.commit();
            } catch (SQLException e) {
                rollbackQuietly(connection);
                throw e;
            } catch (RuntimeException e) {
                rollbackQuietly(connection);
                throw e;
            }
            return result;
        } finally {
            closeQuietly(connection);
        }
    }

    /** True when the database responds - used at startup to fail fast. */
    public boolean isReachable() {
        try {
            Object result = withConnection(new DbWork() {
                @Override
                public Object run(Connection connection) throws SQLException {
                    Statement st = connection.createStatement();
                    try {
                        st.execute("VALUES 1");
                        return Boolean.TRUE;
                    } finally {
                        st.close();
                    }
                }
            });
            return ((Boolean) result).booleanValue();
        } catch (SQLException e) {
            return false;
        }
    }

    private static void closeQuietly(Connection connection) {
        if (connection != null) {
            try {
                connection.close();
            } catch (SQLException ignored) {
                // Nothing useful to do on close failure.
            }
        }
    }

    private static void rollbackQuietly(Connection connection) {
        try {
            connection.rollback();
        } catch (SQLException ignored) {
            // The original exception is more interesting.
        }
    }
}
