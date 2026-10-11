package com.medicalsecurity.util;

/**
 * Hexadecimal encoding helpers. Used for hashes and small binary values in
 * audit/manifest contexts where a printable representation is required.
 */
public final class Hex {

    private static final char[] DIGITS = "0123456789abcdef".toCharArray();

    private Hex() {
    }

    public static String encode(byte[] data) {
        if (data == null) {
            return "";
        }
        char[] out = new char[data.length * 2];
        for (int i = 0; i < data.length; i++) {
            int v = data[i] & 0xFF;
            out[i * 2] = DIGITS[v >>> 4];
            out[i * 2 + 1] = DIGITS[v & 0x0F];
        }
        return new String(out);
    }

    public static byte[] decode(String hex) {
        if (hex == null) {
            return new byte[0];
        }
        String s = hex.trim();
        if ((s.length() & 1) != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = digit(s.charAt(i * 2), i * 2);
            int lo = digit(s.charAt(i * 2 + 1), i * 2 + 1);
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static int digit(char c, int pos) {
        int d = Character.digit(c, 16);
        if (d < 0) {
            throw new IllegalArgumentException("Invalid hex character at position " + pos);
        }
        return d;
    }
}
