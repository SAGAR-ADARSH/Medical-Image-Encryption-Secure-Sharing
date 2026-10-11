package com.medicalsecurity.crypto;

import com.medicalsecurity.util.SecureIds;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * Salted password hashing with the modular-crypt style formats:
 *
 * <ul>
 *   <li>{@code $argon2id$...} - Argon2id via Bouncy Castle when the provider
 *       is on the classpath (preferred),</li>
 *   <li>{@code $pbkdf2-sha512$<iter>$<salt>$<hash>} - PBKDF2-HMAC-SHA512
 *       from the standard JCE (always available; OWASP-approved parameters).</li>
 * </ul>
 *
 * <p>{@link #verify(char[], String)} dispatches on the stored prefix, so
 * accounts hashed with either algorithm keep working across deployments.
 * Passwords are never logged, never persisted in plaintext and compared in
 * constant time.
 */
public final class PasswordHasher {

    public static final String PREFIX_ARGON2ID = "$argon2id$";
    public static final String PREFIX_PBKDF2 = "$pbkdf2-sha512$";

    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final int PBKDF2_DEFAULT_ITERATIONS = 120000;

    // Argon2id parameters (OWASP 2024 baseline: 19 MiB memory, t=2, p=1).
    private static final int ARGON2_MEMORY_KB = 19456;
    private static final int ARGON2_ITERATIONS = 2;
    private static final int ARGON2_PARALLELISM = 1;

    private final int pbkdf2Iterations;
    private final boolean argon2Available;

    public PasswordHasher() {
        this(PBKDF2_DEFAULT_ITERATIONS);
    }

    public PasswordHasher(int pbkdf2Iterations) {
        if (pbkdf2Iterations < 10000) {
            throw new IllegalArgumentException("PBKDF2 iteration count is too low");
        }
        this.pbkdf2Iterations = pbkdf2Iterations;
        this.argon2Available = detectArgon2();
    }

    public String algorithmName() {
        return argon2Available ? "Argon2id (Bouncy Castle)" : "PBKDF2-HMAC-SHA512 (JCE)";
    }

    /** Hashes a password with the strongest available algorithm. */
    public String hash(char[] password) {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Password must not be empty");
        }
        try {
            if (argon2Available) {
                return argon2idHash(password);
            }
            return pbkdf2Hash(password, pbkdf2Iterations);
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    /** Verifies a password against any supported stored hash format. */
    public boolean verify(char[] password, String storedHash) {
        if (password == null || storedHash == null) {
            return false;
        }
        try {
            if (storedHash.startsWith(PREFIX_ARGON2ID)) {
                return argon2Available && argon2idVerify(password, storedHash);
            }
            if (storedHash.startsWith(PREFIX_PBKDF2)) {
                return pbkdf2Verify(password, storedHash);
            }
            return false;
        } finally {
            java.util.Arrays.fill(password, '\0');
        }
    }

    // ------------------------------------------------------------------
    // PBKDF2 (always available)
    // ------------------------------------------------------------------

    private String pbkdf2Hash(char[] password, int iterations) {
        byte[] salt = SecureIds.randomBytes(SALT_BYTES);
        byte[] hash = pbkdf2(password, salt, iterations);
        return PREFIX_PBKDF2 + iterations + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    private boolean pbkdf2Verify(char[] password, String storedHash) {
        String[] parts = storedHash.split("\\$");
        // ["", "pbkdf2-sha512", iter, salt, hash]
        if (parts.length != 5) {
            return false;
        }
        try {
            int iterations = Integer.parseInt(parts[2]);
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            byte[] expected = Base64.getDecoder().decode(parts[4]);
            byte[] actual = pbkdf2(password, salt, iterations);
            return MessageDigest.isEqual(expected, actual);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, HASH_BYTES * 8);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            try {
                return factory.generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2-HMAC-SHA512 unavailable in this JVM", e);
        }
    }

    // ------------------------------------------------------------------
    // Argon2id via Bouncy Castle (reflection: optional dependency)
    // ------------------------------------------------------------------

    private static boolean detectArgon2() {
        try {
            Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    private String argon2idHash(char[] password) {
        try {
            byte[] salt = SecureIds.randomBytes(SALT_BYTES);
            byte[] hash = argon2id(password, salt, ARGON2_ITERATIONS, ARGON2_MEMORY_KB, ARGON2_PARALLELISM);
            return PREFIX_ARGON2ID + "v=19$m=" + ARGON2_MEMORY_KB + ",t=" + ARGON2_ITERATIONS
                    + ",p=" + ARGON2_PARALLELISM + "$"
                    + Base64.getEncoder().encodeToString(salt) + "$"
                    + Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new IllegalStateException("Argon2id hashing failed", e);
        }
    }

    private boolean argon2idVerify(char[] password, String storedHash) {
        try {
            // $argon2id$v=19$m=...,t=...,p=...$salt$hash
            String[] parts = storedHash.split("\\$");
            if (parts.length != 5) {
                return false;
            }
            String params = parts[2];
            int memoryKb = ARGON2_MEMORY_KB;
            int iterations = ARGON2_ITERATIONS;
            int parallelism = ARGON2_PARALLELISM;
            String[] kv = params.split(",");
            for (int i = 0; i < kv.length; i++) {
                String[] pair = kv[i].split("=");
                if (pair.length == 2) {
                    if ("m".equals(pair[0])) {
                        memoryKb = Integer.parseInt(pair[1]);
                    } else if ("t".equals(pair[0])) {
                        iterations = Integer.parseInt(pair[1]);
                    } else if ("p".equals(pair[0])) {
                        parallelism = Integer.parseInt(pair[1]);
                    }
                }
            }
            byte[] salt = Base64.getDecoder().decode(parts[3]);
            byte[] expected = Base64.getDecoder().decode(parts[4]);
            byte[] actual = argon2id(password, salt, iterations, memoryKb, parallelism);
            return MessageDigest.isEqual(expected, actual);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Calls {@code org.bouncycastle.crypto.generators.Argon2BytesGenerator}
     * through reflection so that compiling does not require Bouncy Castle on
     * the classpath (it is declared as a normal Maven dependency, so regular
     * builds get Argon2id automatically).
     */
    private byte[] argon2id(char[] password, byte[] salt, int iterations, int memoryKb, int parallelism)
            throws Exception {
        Class<?> paramsBuilderClass = Class.forName("org.bouncycastle.crypto.params.Argon2Parameters$Builder");
        Class<?> paramsClass = Class.forName("org.bouncycastle.crypto.params.Argon2Parameters");
        int typeArgon2id = paramsClass.getField("ARGON2_id").getInt(null);

        Object builder = paramsBuilderClass.getConstructor(int.class).newInstance(typeArgon2id);
        builder = paramsBuilderClass.getMethod("withSalt", byte[].class).invoke(builder, (Object) salt);
        builder = paramsBuilderClass.getMethod("withParallelism", int.class).invoke(builder, parallelism);
        builder = paramsBuilderClass.getMethod("withMemoryAsKB", int.class).invoke(builder, memoryKb);
        builder = paramsBuilderClass.getMethod("withIterations", int.class).invoke(builder, iterations);
        Object params = paramsBuilderClass.getMethod("build").invoke(builder);

        Class<?> generatorClass = Class.forName("org.bouncycastle.crypto.generators.Argon2BytesGenerator");
        Object generator = generatorClass.getDeclaredConstructor().newInstance();
        generatorClass.getMethod("init", paramsClass).invoke(generator, params);

        byte[] out = new byte[HASH_BYTES];
        generatorClass.getMethod("generateBytes", char[].class, byte[].class, int.class, int.class)
                .invoke(generator, password, out, 0, HASH_BYTES);
        return out;
    }

    /** Small helper for diagnostics; returns a constant, never the hash. */
    public String describe() {
        return "Password hashing: " + algorithmName()
                + (argon2Available ? "" : " (iterations=" + pbkdf2Iterations + ")");
    }
}
