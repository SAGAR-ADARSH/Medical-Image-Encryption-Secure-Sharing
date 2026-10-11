package com.medicalsecurity.service;

import com.medicalsecurity.security.PathGuard;
import com.medicalsecurity.util.IoUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

/**
 * Secure storage for ENCRYPTED payloads only. Files live under a dedicated
 * directory outside the application tree ({@code MEDSEC_STORAGE_DIR}); the
 * database stores only a safe relative reference. Path traversal is rejected
 * by {@link PathGuard}.
 */
public final class StorageService {

    private static final String EXTENSION = ".bin";

    private final PathGuard guard;
    private final long maxFileBytes;

    public StorageService(PathGuard guard, long maxFileBytes) {
        this.guard = guard;
        this.maxFileBytes = maxFileBytes;
    }

    /**
     * Stores the ciphertext under its transfer id and returns the relative
     * storage reference persisted in the database.
     */
    public String storeEncrypted(String transferId, byte[] ciphertext) throws IOException {
        if (transferId == null || !transferId.matches("[0-9a-fA-F-]{36}")) {
            throw new IOException("Invalid transfer id for storage");
        }
        if (ciphertext == null || ciphertext.length == 0) {
            throw new IOException("Refusing to store an empty payload");
        }
        if (ciphertext.length > maxFileBytes) {
            throw new IOException("Payload exceeds the configured maximum size");
        }
        guard.ensureBaseDir();
        String name = transferId + EXTENSION;
        Path target = guard.resolveInside(name);
        Path tmp = guard.resolveInside(name + ".part");
        Files.write(tmp, ciphertext);
        try {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
        return guard.toRelativeRef(target);
    }

    /** Loads a stored payload (bounded). */
    public byte[] loadEncrypted(String storageRef) throws IOException {
        Path file = guard.resolveInside(storageRef);
        return IoUtils.readFileBounded(file, maxFileBytes);
    }

    public boolean exists(String storageRef) {
        try {
            Path file = guard.resolveInside(storageRef);
            return Files.isRegularFile(file);
        } catch (IOException e) {
            return false;
        }
    }

    public void deleteEncrypted(String storageRef) throws IOException {
        Files.deleteIfExists(guard.resolveInside(storageRef));
    }

    public PathGuard getGuard() {
        return guard;
    }
}
