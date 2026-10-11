package com.medicalsecurity.support;

import com.medicalsecurity.dao.DaoFactory;
import com.medicalsecurity.dao.Database;
import com.medicalsecurity.dao.SchemaInitializer;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Test support: creates a fresh in-memory Derby database with the standard
 * schema for every test class. The DAO layer under test is the SAME code the
 * MySQL deployment uses (only the JDBC driver/URL differ).
 */
public final class TestSupport {

    private TestSupport() {
    }

    /** One configured, schema-initialised test database (in-memory). */
    public static final class TestDb {
        public final Database database;
        public final DaoFactory daos;

        TestDb(Database database) {
            this.database = database;
            this.daos = new DaoFactory(database);
        }
    }

    private static int counter = 0;

    public static TestDb newDatabase() {
        int id;
        synchronized (TestSupport.class) {
            id = counter++;
        }
        final String url = "jdbc:derby:memory:testdb" + id + ";create=true";
        Database database = new Database("org.apache.derby.jdbc.EmbeddedDriver", url, "", "");
        try {
            String script = new String(Files.readAllBytes(schemaPath()), StandardCharsets.UTF_8);
            SchemaInitializer.applyScript(database, script);
        } catch (Exception e) {
            throw new IllegalStateException("Could not initialise the test database", e);
        }
        return new TestDb(database);
    }

    static Path schemaPath() {
        final Path direct = Paths.get("sql", "schema-derby.sql");
        if (Files.isRegularFile(direct)) {
            return direct;
        }
        // Fallback when tests run from a different working directory.
        final Path fromModule = Paths.get("..", "sql", "schema-derby.sql");
        if (Files.isRegularFile(fromModule)) {
            return fromModule;
        }
        throw new IllegalStateException("sql/schema-derby.sql not found (run tests from the project root)");
    }
}
