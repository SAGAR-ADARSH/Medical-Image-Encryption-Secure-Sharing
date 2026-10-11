package com.medicalsecurity.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Path traversal tests (spec section 11).
 */
class PathGuardTest {

    private static PathGuard guard() {
        return new PathGuard(Paths.get("data", "storage").toAbsolutePath());
    }

    @Test
    @DisplayName("Paths inside the storage root are accepted")
    void insideRootAllowed() throws Exception {
        PathGuard g = guard();
        Path resolved = g.resolveInside("1-2-uuid.bin");
        assertTrue(resolved.startsWith(g.baseDir()));
        g.requireInside(resolved);
    }

    @Test
    @DisplayName("Directory-traversal style names are rejected")
    void traversalRejected() {
        final PathGuard g = guard();
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g.resolveInside("../../etc/passwd");
            }
        });
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g.resolveInside("a/../../b.bin");
            }
        });
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g.resolveInside("bad\u0000name.bin");
            }
        });
    }

    @Test
    @DisplayName("Empty and null references are rejected")
    void emptyRejected() {
        final PathGuard g = guard();
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g.resolveInside("");
            }
        });
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g.resolveInside(null);
            }
        });
    }

    @Test
    @DisplayName("requireInside detects escapes from the root")
    void requireInsideDetectsEscapes() throws Exception {
        PathGuard g = guard();
        g.requireInside(g.baseDir().resolve("file.bin"));
        final PathGuard g2 = g;
        assertThrows(java.io.IOException.class, new org.junit.jupiter.api.function.Executable() {
            @Override
            public void execute() throws Throwable {
                g2.requireInside(g2.baseDir().resolve("..").resolve("other").resolve("x.bin"));
            }
        });
        assertFalse(g.baseDir().resolve("..").resolve("x.bin").normalize()
                .startsWith(g.baseDir().normalize()));
    }

    @Test
    @DisplayName("Relative references round-trip through toRelativeRef")
    void relativeRefRoundTrip() throws Exception {
        PathGuard g = guard();
        Path resolved = g.resolveInside("subdir/file.bin");
        String ref = g.toRelativeRef(resolved);
        assertTrue("subdir/file.bin".equals(ref) || "subdir\\file.bin".equals(ref),
                "round-trip produces a portable reference, got: " + ref);
    }
}
