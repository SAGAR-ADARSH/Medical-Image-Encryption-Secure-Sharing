package com.medicalsecurity.dao;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/**
 * Applies a SQL schema script (resources) to the configured database.
 * Statements are separated by ';' at line ends; '--' comments are stripped.
 * Idempotent scripts ({@code CREATE TABLE IF NOT EXISTS} on MySQL) make the
 * operation safe to repeat.
 */
public final class SchemaInitializer {

    private SchemaInitializer() {
    }

    /** Loads a schema script from the classpath and executes it. */
    public static void applyClasspathSchema(Database database, final String resourcePath)
            throws SQLException {
        String script = readResource(resourcePath);
        applyScript(database, script);
    }

    public static void applyScript(Database database, final String script) throws SQLException {
        final List<String> statements = splitStatements(script);
        database.inTransaction(new Database.DbWork() {
            @Override
            public Object run(Connection connection) throws SQLException {
                Statement statement = connection.createStatement();
                try {
                    for (int i = 0; i < statements.size(); i++) {
                        String sql = (String) statements.get(i);
                        try {
                            statement.execute(sql);
                        } catch (SQLException e) {
                            throw new SQLException("Schema statement failed: "
                                    + abbreviate(sql) + " -> " + e.getMessage(), e);
                        }
                    }
                } finally {
                    statement.close();
                }
                return Integer.valueOf(statements.size());
            }
        });
    }

    public static String readResource(String resourcePath) {
        InputStream in = SchemaInitializer.class.getClassLoader().getResourceAsStream(resourcePath);
        if (in == null) {
            throw new IllegalArgumentException("Schema resource not found: " + resourcePath);
        }
        StringBuilder sb = new StringBuilder();
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
        } catch (IOException e) {
            throw new IllegalStateException("Cannot read schema resource: " + resourcePath, e);
        } finally {
            try {
                in.close();
            } catch (IOException ignored) {
                // best effort
            }
        }
        return sb.toString();
    }

    public static List<String> splitStatements(String script) {
        List<String> out = new ArrayList<String>();
        StringBuilder current = new StringBuilder();
        String[] lines = script.split("\n");
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            int comment = line.indexOf("--");
            if (comment >= 0) {
                line = line.substring(0, comment);
            }
            line = line.trim();
            if (line.isEmpty()) {
                continue;
            }
            current.append(line).append(' ');
            if (line.endsWith(";")) {
                String sql = current.toString().trim();
                sql = sql.substring(0, sql.length() - 1).trim();
                if (!sql.isEmpty()) {
                    out.add(sql);
                }
                current.setLength(0);
            }
        }
        String tail = current.toString().trim();
        if (!tail.isEmpty()) {
            if (tail.endsWith(";")) {
                tail = tail.substring(0, tail.length() - 1);
            }
            if (!tail.trim().isEmpty()) {
                out.add(tail.trim());
            }
        }
        return out;
    }

    private static String abbreviate(String sql) {
        return sql.length() > 120 ? sql.substring(0, 117) + "..." : sql;
    }
}
