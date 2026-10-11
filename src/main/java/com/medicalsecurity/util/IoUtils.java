package com.medicalsecurity.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Stream helpers with mandatory size limits. Every network or file read of an
 * unbounded payload must go through these methods so a hostile peer cannot
 * exhaust memory (defence against oversize frames / files).
 */
public final class IoUtils {

    private IoUtils() {
    }

    /** Reads the full stream but fails hard if more than {@code maxBytes} arrive. */
    public static byte[] readAllBounded(InputStream in, long maxBytes) throws IOException {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("maxBytes must be positive");
        }
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("Input exceeds the maximum allowed size of " + maxBytes + " bytes");
            }
            buffer.write(chunk, 0, n);
        }
        return buffer.toByteArray();
    }

    /** Reads a whole file with a hard size cap. */
    public static byte[] readFileBounded(Path file, long maxBytes) throws IOException {
        if (!Files.isRegularFile(file)) {
            throw new IOException("Not a regular file: " + file.getFileName());
        }
        long size = Files.size(file);
        if (size > maxBytes) {
            throw new IOException("File exceeds the maximum allowed size of " + maxBytes + " bytes");
        }
        return Files.readAllBytes(file);
    }

    /** Writes the full buffer, looping until everything is flushed to the socket/file. */
    public static void writeFully(OutputStream out, byte[] data) throws IOException {
        out.write(data);
        out.flush();
    }

    /** Copies with a hard cap; returns bytes copied. */
    public static long copyBounded(InputStream in, OutputStream out, long maxBytes) throws IOException {
        byte[] chunk = new byte[8192];
        long total = 0;
        int n;
        while ((n = in.read(chunk)) != -1) {
            total += n;
            if (total > maxBytes) {
                throw new IOException("Stream exceeds the maximum allowed size of " + maxBytes + " bytes");
            }
            out.write(chunk, 0, n);
        }
        out.flush();
        return total;
    }
}
