package com.medicalsecurity.util;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Input validation and filename sanitisation. All user-supplied names and
 * paths must pass through this class before they reach the database, the
 * filesystem or the network protocol.
 */
public final class Validation {

    /** Usernames: 3-64 chars of letters, digits, dot, dash, underscore. */
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._-]{3,64}$");

    /** Conservative display names. */
    private static final Pattern FULL_NAME = Pattern.compile("^[A-Za-z0-9 .,'()_-]{2,120}$");

    private Validation() {
    }

    public static boolean isBlank(String s) {
        return s == null || s.trim().isEmpty();
    }

    public static String requireNonBlank(String value, String fieldName) {
        if (isBlank(value)) {
            throw new IllegalArgumentException(fieldName + " must not be blank");
        }
        return value.trim();
    }

    public static boolean isValidUsername(String username) {
        return username != null && USERNAME.matcher(username).matches();
    }

    public static void requireValidUsername(String username) {
        if (!isValidUsername(username)) {
            throw new IllegalArgumentException(
                    "Username must be 3-64 characters (letters, digits, '.', '-', '_')");
        }
    }

    public static boolean isValidFullName(String fullName) {
        return fullName != null && FULL_NAME.matcher(fullName).matches();
    }

    public static void requireValidFullName(String fullName) {
        if (!isValidFullName(fullName)) {
            throw new IllegalArgumentException("Full name contains unsupported characters");
        }
    }

    /**
     * Returns a safe base filename (no directories, no traversal sequences).
     * The result is guaranteed to contain only [A-Za-z0-9._-] and to never be
     * empty or "." / "..".
     */
    public static String sanitizeFilename(String rawName) {
        if (isBlank(rawName)) {
            throw new IllegalArgumentException("Filename must not be blank");
        }
        // Strip any directory components (covers both '/' and '\\' paths).
        String name = rawName.trim();
        int slash = Math.max(name.lastIndexOf('/'), name.lastIndexOf('\\'));
        if (slash >= 0) {
            name = name.substring(slash + 1);
        }
        if (name.isEmpty() || ".".equals(name) || "..".equals(name)) {
            throw new IllegalArgumentException("Illegal filename");
        }
        if (name.contains("..")) {
            throw new IllegalArgumentException("Filename must not contain '..'");
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-') {
                sb.append(c);
            } else {
                sb.append('_');
            }
        }
        String cleaned = sb.toString();
        while (cleaned.startsWith(".")) {
            cleaned = cleaned.substring(1);
        }
        if (cleaned.isEmpty()) {
            cleaned = "image.bin";
        }
        if (cleaned.length() > 200) {
            cleaned = cleaned.substring(cleaned.length() - 200);
        }
        return cleaned;
    }

    public static boolean isSupportedImageFilename(String name) {
        if (isBlank(name)) {
            return false;
        }
        String lower = name.trim().toLowerCase(Locale.ROOT);
        return lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                || lower.endsWith(".bmp") || lower.endsWith(".gif");
    }

    public static void requireSupportedImageFilename(String name) {
        if (!isSupportedImageFilename(name)) {
            throw new IllegalArgumentException(
                    "Unsupported image type. Allowed: .png .jpg .jpeg .bmp .gif");
        }
    }

    public static void requireValidPort(int port, String fieldName) {
        if (port < 1024 || port > 65535) {
            throw new IllegalArgumentException(fieldName + " must be between 1024 and 65535");
        }
    }

    /** Short, secret-free detail strings for audit rows and status errors. */
    public static String sanitizeDetail(String detail) {
        if (detail == null) {
            return null;
        }
        String d = detail.trim();
        if (d.length() > 250) {
            d = d.substring(0, 250);
        }
        return d;
    }

    public static long requirePositive(long value, String fieldName) {
        if (value <= 0) {
            throw new IllegalArgumentException(fieldName + " must be positive");
        }
        return value;
    }
}
