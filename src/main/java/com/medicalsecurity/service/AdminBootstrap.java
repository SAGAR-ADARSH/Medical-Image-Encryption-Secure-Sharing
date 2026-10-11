package com.medicalsecurity.service;

import com.medicalsecurity.config.AppConfig;
import com.medicalsecurity.dao.Database;
import com.medicalsecurity.dao.SchemaInitializer;
import com.medicalsecurity.network.ServerContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Installation-time tool:
 * <ol>
 *   <li>applies the SQL schema to the configured database,</li>
 *   <li>creates the first administrator account (if missing).</li>
 * </ol>
 *
 * <p>Usage:
 * <pre>
 *   mvn exec:java -Dexec.mainClass=com.medicalsecurity.service.AdminBootstrap \
 *       -Dexec.args="sql/schema.sql admin 'ChangeMe123!' 'System Administrator'"
 * </pre>
 * The administrator password should be supplied via
 * {@code MEDSEC_ADMIN_PASSWORD} instead of the command line where possible.
 */
public final class AdminBootstrap {

    public static void main(String[] args) throws Exception {
        AppConfig config = AppConfig.load();
        String schemaPath = args.length > 0 ? args[0] : defaultSchema(config);
        String adminUser = args.length > 1 ? args[1] : "admin";
        String adminPassword = args.length > 2 ? args[2] : System.getenv("MEDSEC_ADMIN_PASSWORD");
        String adminFullName = args.length > 3 ? args[3] : "System Administrator";
        if (adminPassword == null || adminPassword.isEmpty()) {
            adminPassword = "ChangeMe123!";
            System.out.println("[bootstrap] MEDSEC_ADMIN_PASSWORD not set - using the documented demo default.");
        }

        System.out.println("[bootstrap] applying schema: " + schemaPath);
        String script = readSchema(schemaPath);
        Database database = Database.fromConfig(config);
        SchemaInitializer.applyScript(database, script);
        System.out.println("[bootstrap] schema applied.");

        ServerContext context = new ServerContext(config);
        if (context.daos.users().findByUsername(adminUser) != null) {
            System.out.println("[bootstrap] administrator '" + adminUser + "' already exists - nothing to do.");
            return;
        }
        UserAdminService userAdmin = context.userAdmin;
        com.medicalsecurity.model.User admin = userAdmin.createInitialAdmin(
                adminUser, adminPassword, adminFullName, "localhost");
        System.out.println("[bootstrap] created administrator '" + admin.getUsername()
                + "' (id=" + admin.getId() + ").");
        System.out.println("[bootstrap] password hashing: " + context.passwordHasher.describe());
    }

    static String defaultSchema(AppConfig config) {
        String driver = config.getDbDriver();
        if (driver != null && driver.toLowerCase(java.util.Locale.ROOT).contains("derby")) {
            return "sql/schema-derby.sql";
        }
        return "sql/schema.sql";
    }

    static String readSchema(String schemaPath) throws Exception {
        Path path = Paths.get(schemaPath);
        if (Files.isRegularFile(path)) {
            return new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        }
        // Fall back to the classpath copy (if packaged).
        String resource = schemaPath.startsWith("sql/") ? schemaPath : "sql/" + schemaPath;
        return SchemaInitializer.readResource(resource);
    }
}
