package com.medicalsecurity.network;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

/**
 * Bounded binary I/O helpers for the socket protocol. Every read is capped;
 * malformed or oversized frames are rejected with an {@link IOException}
 * instead of exhausting memory.
 */
public final class MessageIO {

    /** Hard cap for any single byte-array frame (ciphertext + headroom). */
    public static final int MAX_FRAME_BYTES = 32 * 1024 * 1024;

    private MessageIO() {
    }

    public static DataInputStream in(Socket socket) throws IOException {
        socket.setSoTimeout(socket.getSoTimeout());
        return new DataInputStream(socket.getInputStream());
    }

    public static DataOutputStream out(Socket socket) throws IOException {
        return new DataOutputStream(socket.getOutputStream());
    }

    /** Writes a byte array with a 32-bit length prefix. */
    public static void writeBytes(DataOutputStream out, byte[] data) throws IOException {
        if (data == null) {
            out.writeInt(0);
            return;
        }
        if (data.length > MAX_FRAME_BYTES) {
            throw new IOException("Outgoing frame exceeds " + MAX_FRAME_BYTES + " bytes");
        }
        out.writeInt(data.length);
        out.write(data);
        out.flush();
    }

    /** Reads a length-prefixed byte array with a hard cap. */
    public static byte[] readBytes(DataInputStream in) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > MAX_FRAME_BYTES) {
            throw new IOException("Invalid frame length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    /** Reads a byte array but rejects anything above {@code maxBytes}. */
    public static byte[] readBytes(DataInputStream in, int maxBytes) throws IOException {
        int length = in.readInt();
        if (length < 0 || length > maxBytes) {
            throw new IOException("Invalid frame length: " + length);
        }
        byte[] data = new byte[length];
        in.readFully(data);
        return data;
    }

    /** Writes a UTF string (already limited to 64 KiB by the DataOutput format). */
    public static void writeString(DataOutputStream out, String value) throws IOException {
        out.writeUTF(value == null ? "" : value);
    }

    /** Reads a UTF string, treating {@code null} as empty. */
    public static String readString(DataInputStream in) throws IOException {
        String value = in.readUTF();
        return value == null ? "" : value;
    }

    /** Applies a socket timeout; small helper to keep call sites consistent. */
    public static void configure(Socket socket, int timeoutMs) throws IOException {
        socket.setSoTimeout(Math.max(1000, timeoutMs));
        socket.setTcpNoDelay(true);
    }

    /** Copies a bounded payload (used when relaying images to disk). */
    public static byte[] readBoundedPayload(DataInputStream in, long maxBytes) throws IOException {
        long declared = in.readInt();
        if (declared < 0 || declared > maxBytes || declared > MAX_FRAME_BYTES) {
            throw new IOException("Payload size out of bounds: " + declared);
        }
        byte[] data = new byte[(int) declared];
        in.readFully(data);
        return data;
    }
}
