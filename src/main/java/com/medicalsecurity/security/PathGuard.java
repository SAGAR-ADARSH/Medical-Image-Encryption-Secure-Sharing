package com.medicalsecurity.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Path traversal protection. Every file access derived from a network request
 * or a database reference must be resolved through this guard so that values
 * like {@code ../../etc/passwd} can never escape the designated base
 * directory (the encrypted-payload storage area).
 */
public final class PathGuard {

    private final Path baseDir;

    public PathGuard(Path baseDir) {
        if (baseDir == null) {
            throw new IllegalArgumentException("baseDir must not be null");
        }
        this.baseDir = baseDir.toAbsolutePath().normalize();
    }

    public Path baseDir() {
        return baseDir;
    }

    /**
     * Resolves a relative reference inside the base directory and verifies the
     * canonical result stays within it.
     */
    public Path resolveInside(String relativeRef) throws IOException {
        if (relativeRef == null || relativeRef.trim().isEmpty()) {
            throw new IOException("Empty storage reference");
        }
        String ref = relativeRef.trim();
        if (ref.indexOf('\0') >= 0) {
            throw new IOException("Illegal character in storage reference");
        }
        Path resolved = baseDir.resolve(ref).normalize();
        if (!resolved.startsWith(baseDir)) {
            throw new IOException("Path traversal attempt rejected");
        }
        return resolved;
    }

    /** Same check for already-built paths. */
    public Path requireInside(Path candidate) throws IOException {
        if (candidate == null) {
            throw new IOException("Null path");
        }
        Path normalized = candidate.toAbsolutePath().normalize();
        if (!normalized.startsWith(baseDir)) {
            throw new IOException("Path escapes the allowed base directory");
        }
        return normalized;
    }

    /** Converts an absolute path below the base dir into a portable relative reference. */
    public String toRelativeRef(Path file) throws IOException {
        Path normalized = requireInside(file);
        return baseDir.relativize(normalized).toString().replace('\\', '/');
    }

    /** Creates the base directory when missing (with restrictive permissions). */
    public void ensureBaseDir() throws IOException {
        Files.createDirectories(baseDir);
    }
}
