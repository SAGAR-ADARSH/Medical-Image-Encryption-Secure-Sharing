package com.medicalsecurity.config;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Properties;

/**
 * Environment-based application configuration.
 *
 * <p>Values are resolved in this order (first hit wins):
 * <ol>
 *   <li>JVM system properties ({@code -Dmedsec.db.url=...}),</li>
 *   <li>OS environment variables ({@code MEDSEC_DB_URL=...}),</li>
 *   <li>an optional properties file ({@code $MEDSEC_CONFIG} or
 *       {@code ~/.med-image-security/config.properties}),</li>
 *   <li>documented defaults suitable for a local demonstration.</li>
 * </ol>
 *
 * <p>Secrets (database password, keystore password) are never logged and
 * never written back to disk by this class. Real deployments must provide
 * them through the environment; the defaults are only for a local demo.
 */
public final class AppConfig {

    public static final String DEFAULT_DB_DRIVER = "com.mysql.cj.jdbc.Driver";
    public static final String DEFAULT_DB_URL =
            "jdbc:mysql://localhost:3306/medical_security?useSSL=false&allowPublicKeyRetrieval=true&serverTimezone=UTC";
    public static final int DEFAULT_KEYMGR_PORT = 7500;
    public static final int DEFAULT_TRANSFER_PORT = 7501;
    public static final long DEFAULT_MAX_FILE_BYTES = 25L * 1024L * 1024L; // 25 MiB

    private final Properties fileProps;

    private AppConfig(Properties fileProps) {
        this.fileProps = fileProps;
    }

    public static AppConfig load() {
        return new AppConfig(loadFileProperties());
    }

    private static Properties loadFileProperties() {
        Properties props = new Properties();
        String explicit = firstNonBlank(System.getProperty("medsec.config"), System.getenv("MEDSEC_CONFIG"));
        Path candidate;
        if (explicit != null) {
            candidate = Paths.get(explicit);
        } else {
            Path home = Paths.get(System.getProperty("user.home", "."));
            candidate = home.resolve(".med-image-security").resolve("config.properties");
        }
        if (Files.isRegularFile(candidate)) {
            Reader reader = null;
            try {
                reader = Files.newBufferedReader(candidate);
                props.load(reader);
            } catch (IOException e) {
                // Configuration file problems must not leak details; fall back to defaults/env.
                System.err.println("[config] Could not read " + candidate.getFileName() + "; using environment/defaults.");
            } finally {
                if (reader != null) {
                    try {
                        reader.close();
                    } catch (IOException ignored) {
                        // best effort
                    }
                }
            }
        }
        return props;
    }

    // ------------------------------------------------------------------
    // Resolution helpers
    // ------------------------------------------------------------------

    private String resolve(String key, String dflt) {
        String v = firstNonBlank(
                System.getProperty("medsec." + key.toLowerCase(Locale.ROOT).replace('_', '.')),
                System.getenv("MEDSEC_" + key),
                fileProps.getProperty(key));
        return v != null ? v.trim() : dflt;
    }

    private long resolveLong(String key, long dflt) {
        String v = resolve(key, null);
        if (v == null) {
            return dflt;
        }
        try {
            return Long.parseLong(v.trim());
        } catch (NumberFormatException e) {
            throw new IllegalStateException("Invalid numeric configuration for " + key);
        }
    }

    private static String firstNonBlank(String... values) {
        for (int i = 0; i < values.length; i++) {
            if (values[i] != null && !values[i].trim().isEmpty()) {
                return values[i];
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Database
    // ------------------------------------------------------------------

    public String getDbDriver() {
        return resolve("DB_DRIVER", DEFAULT_DB_DRIVER);
    }

    public String getDbUrl() {
        return resolve("DB_URL", DEFAULT_DB_URL);
    }

    public String getDbUser() {
        return resolve("DB_USER", "medsec");
    }

    /** Database password - never log the result. */
    public String getDbPassword() {
        String pw = resolve("DB_PASSWORD", "");
        return pw != null ? pw : "";
    }

    // ------------------------------------------------------------------
    // Storage / keystores
    // ------------------------------------------------------------------

    /** Directory that holds ENCRYPTED payloads only, outside the application tree. */
    public Path getStorageDir() {
        return Paths.get(resolve("STORAGE_DIR", defaultDataDir("storage"))).toAbsolutePath().normalize();
    }

    /** Directory that holds PKCS#12 keystores (private keys). Never served over the network. */
    public Path getKeystoreDir() {
        return Paths.get(resolve("KEYSTORE_DIR", defaultDataDir("keystores"))).toAbsolutePath().normalize();
    }

    /** Password protecting local PKCS#12 keystores - never log the result. */
    public String getKeystorePassword() {
        String pw = resolve("KEYSTORE_PASSWORD", "medsec-demo-keystore");
        return pw != null ? pw : "";
    }

    private static String defaultDataDir(String child) {
        String home = System.getProperty("user.home", ".");
        return Paths.get(home, "med-image-security", child).toString();
    }

    // ------------------------------------------------------------------
    // Network
    // ------------------------------------------------------------------

    public String getServerHost() {
        return resolve("SERVER_HOST", "127.0.0.1");
    }

    public int getKeyManagerPort() {
        return (int) resolveLong("KEYMGR_PORT", DEFAULT_KEYMGR_PORT);
    }

    public int getTransferPort() {
        return (int) resolveLong("TRANSFER_PORT", DEFAULT_TRANSFER_PORT);
    }

    public int getSocketTimeoutMs() {
        return (int) resolveLong("SOCKET_TIMEOUT_MS", 30000);
    }

    public long getMaxFileBytes() {
        return resolveLong("MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES);
    }

    // ------------------------------------------------------------------
    // Optional TLS for the socket protocol
    // ------------------------------------------------------------------

    public boolean isTlsEnabled() {
        return Boolean.parseBoolean(resolve("TLS_ENABLED", "false"));
    }

    public String getTlsKeystore() {
        return resolve("TLS_KEYSTORE", null);
    }

    public String getTlsKeystorePassword() {
        String pw = resolve("TLS_KEYSTORE_PASSWORD", "");
        return pw != null ? pw : "";
    }

    public String getTlsTruststore() {
        return resolve("TLS_TRUSTSTORE", null);
    }

    public String getTlsTruststorePassword() {
        String pw = resolve("TLS_TRUSTSTORE_PASSWORD", "");
        return pw != null ? pw : "";
    }

    // ------------------------------------------------------------------
    // Password hashing
    // ------------------------------------------------------------------

    public int getPbkdf2Iterations() {
        return (int) resolveLong("PBKDF2_ITERATIONS", 120000);
    }

    /**
     * Human-readable summary for the settings screen. Secrets are redacted.
     */
    public String describe() {
        StringBuilder sb = new StringBuilder();
        sb.append("Database driver   : ").append(getDbDriver()).append('\n');
        sb.append("Database URL      : ").append(getDbUrl()).append('\n');
        sb.append("Database user     : ").append(getDbUser()).append('\n');
        sb.append("Database password : ").append(getDbPassword().isEmpty() ? "(empty)" : "********").append('\n');
        sb.append("Storage directory : ").append(getStorageDir()).append('\n');
        sb.append("Keystore directory: ").append(getKeystoreDir()).append('\n');
        sb.append("Keystore password : ").append(getKeystorePassword().isEmpty() ? "(empty)" : "********").append('\n');
        sb.append("Server host       : ").append(getServerHost()).append('\n');
        sb.append("Key-manager port  : ").append(getKeyManagerPort()).append('\n');
        sb.append("Transfer port     : ").append(getTransferPort()).append('\n');
        sb.append("Socket timeout    : ").append(getSocketTimeoutMs()).append(" ms\n");
        sb.append("Max image size    : ").append(getMaxFileBytes() / 1024).append(" KiB\n");
        sb.append("TLS               : ").append(isTlsEnabled() ? "enabled" : "disabled (localhost demo)").append('\n');
        return sb.toString();
    }
}
