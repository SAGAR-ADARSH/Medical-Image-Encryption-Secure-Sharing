package com.medicalsecurity.crypto;

import com.medicalsecurity.util.Validation;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;

/**
 * PKCS#12 keystore management for recipient key pairs.
 *
 * <p>Private keys are generated IN-PROCESS (JCE {@code KeyPairGenerator}) and
 * written directly into {@code <keystoreDir>/<username>.p12} together with a
 * self-signed certificate that carries the matching public key. Private keys
 * are NEVER exported through the database, the network protocol or the UI.
 * The keystore password comes from the environment
 * ({@code MEDSEC_KEYSTORE_PASSWORD}); the demo default is documented in the
 * README.
 *
 * <p>Deployment note: in a two-machine setup the administrator copies the
 * freshly provisioned {@code .p12} file to the recipient's machine (like
 * distributing a hardware token) over a trusted channel.
 */
public final class KeystoreService {

    public static final String KEY_ALIAS = "user-key";
    public static final String KEY_ALGORITHM = "RSA";
    public static final int KEY_SIZE_BITS = 2048;
    public static final int CERT_VALIDITY_DAYS = 3650;

    private final Path keystoreDir;
    private final String keystorePassword;

    public KeystoreService(Path keystoreDir, String keystorePassword) {
        this.keystoreDir = keystoreDir.toAbsolutePath().normalize();
        this.keystorePassword = keystorePassword == null ? "" : keystorePassword;
    }

    public Path keystoreDir() {
        return keystoreDir;
    }

    public Path keystorePathFor(String username) {
        Validation.requireValidUsername(username);
        return keystoreDir.resolve(username + ".p12");
    }

    public boolean hasKeyStore(String username) {
        return Files.isRegularFile(keystorePathFor(username));
    }

    /**
     * Provisions a new RSA key pair for the user inside a fresh PKCS#12 file
     * and returns the public key.
     */
    public synchronized PublicKey provisionKeyPair(String username) throws IOException {
        Validation.requireValidUsername(username);
        Files.createDirectories(keystoreDir);
        Path target = keystorePathFor(username);
        if (Files.exists(target)) {
            throw new IOException("A keystore already exists for user " + username);
        }
        try {
            KeyPair keyPair = new KeyProtector().generateRecipientKeyPair();
            X509Certificate certificate = SelfSignedCertificate.create(
                    username, keyPair.getPublic(), keyPair.getPrivate(), CERT_VALIDITY_DAYS);

            KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(null, keystorePassword.toCharArray());
            Certificate[] chain = new Certificate[]{certificate};
            store.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(),
                    keystorePassword.toCharArray(), chain);

            OutputStream out = Files.newOutputStream(target);
            try {
                store.store(out, keystorePassword.toCharArray());
            } finally {
                out.close();
            }
            restrictPermissions(target);
            return keyPair.getPublic();
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("Could not provision a key pair for " + username, e);
        }
    }

    private static void restrictPermissions(Path file) {
        try {
            file.toFile().setReadable(false, false);
            file.toFile().setReadable(true, true);
            file.toFile().setWritable(false, false);
            file.toFile().setWritable(true, true);
        } catch (SecurityException ignored) {
            // Best effort on platforms without POSIX permissions.
        }
    }

    /** Loads the recipient PUBLIC key (safe to share). */
    public PublicKey loadPublicKey(String username) throws IOException {
        try {
            KeyStore store = loadStore(username);
            Certificate cert = store.getCertificate(KEY_ALIAS);
            if (cert == null) {
                throw new IOException("No certificate for alias " + KEY_ALIAS);
            }
            return cert.getPublicKey();
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("Cannot read keystore for " + username, e);
        }
    }

    /** Loads the recipient PRIVATE key. Never log or transmit the result. */
    public PrivateKey loadPrivateKey(String username) throws IOException {
        try {
            KeyStore store = loadStore(username);
            KeyStore.ProtectionParameter prot =
                    new KeyStore.PasswordProtection(keystorePassword.toCharArray());
            KeyStore.PrivateKeyEntry entry =
                    (KeyStore.PrivateKeyEntry) store.getEntry(KEY_ALIAS, prot);
            if (entry == null) {
                throw new IOException("No private key for alias " + KEY_ALIAS);
            }
            return entry.getPrivateKey();
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("Cannot read private key for " + username, e);
        }
    }

    /** X.509 SubjectPublicKeyInfo (DER) - the form stored in the database. */
    public byte[] publicKeyDer(String username) throws IOException {
        return loadPublicKey(username).getEncoded();
    }

    /** Rebuilds a PublicKey from stored DER bytes. */
    public static PublicKey publicKeyFromDer(byte[] der) throws IOException {
        try {
            return KeyFactory.getInstance(KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(der));
        } catch (java.security.GeneralSecurityException e) {
            throw new IOException("Invalid public key encoding", e);
        }
    }

    private KeyStore loadStore(String username) throws java.security.GeneralSecurityException, IOException {
        Path file = keystorePathFor(username);
        if (!Files.isRegularFile(file)) {
            throw new IOException("No keystore for user " + username);
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        InputStream in = Files.newInputStream(file);
        try {
            store.load(in, keystorePassword.toCharArray());
        } finally {
            in.close();
        }
        return store;
    }

    /** Replaces a keystore atomically when re-provisioning. */
    public synchronized void deleteKeyStore(String username) throws IOException {
        Files.deleteIfExists(keystorePathFor(username));
    }
}
