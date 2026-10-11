package com.medicalsecurity.network;

import com.medicalsecurity.config.AppConfig;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

/**
 * Optional TLS for the socket protocol.
 *
 * <p>AES-GCM protects the image payload end-to-end, but transfer metadata and
 * login credentials should also travel over an authenticated channel when the
 * network is untrusted. When {@code MEDSEC_TLS_ENABLED=true} the servers use
 * an SSLServerSocket backed by a PKCS#12 keystore and the clients use an
 * SSLSocket backed by a truststore (both created with {@code keytool}; see
 * the README "TLS configuration" section). When TLS is disabled the demo runs
 * over plain TCP on localhost only - documented as an academic trade-off.
 */
public final class SslSupport {

    private SslSupport() {
    }

    public static ServerSocket createServerSocket(AppConfig config, int port) throws IOException {
        if (!config.isTlsEnabled()) {
            return new ServerSocket(port);
        }
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            KeyStore keyStore = loadStore(config.getTlsKeystore(), config.getTlsKeystorePassword());
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, config.getTlsKeystorePassword().toCharArray());
            KeyStore trustStore = loadStore(config.getTlsTruststore(), config.getTlsTruststorePassword());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
            SSLServerSocketFactory factory = context.getServerSocketFactory();
            return factory.createServerSocket(port);
        } catch (GeneralSecurityException e) {
            throw new IOException("Cannot initialise TLS for the server socket", e);
        }
    }

    public static Socket createClientSocket(AppConfig config, String host, int port, int timeoutMs)
            throws IOException {
        if (!config.isTlsEnabled()) {
            Socket socket = new Socket();
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            MessageIO.configure(socket, timeoutMs);
            return socket;
        }
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            KeyStore trustStore = loadStore(config.getTlsTruststore(), config.getTlsTruststorePassword());
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            context.init(null, tmf.getTrustManagers(), null);
            SSLSocketFactory factory = context.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.setTcpNoDelay(true);
            socket.startHandshake();
            return socket;
        } catch (GeneralSecurityException e) {
            throw new IOException("Cannot initialise TLS for the client socket", e);
        }
    }

    private static KeyStore loadStore(String location, String password) throws IOException, GeneralSecurityException {
        if (location == null || location.trim().isEmpty()) {
            throw new IOException("TLS is enabled but no keystore/truststore location is configured");
        }
        Path path = Paths.get(location.trim());
        if (!Files.isRegularFile(path)) {
            throw new IOException("TLS store not found: " + path.getFileName());
        }
        KeyStore store = KeyStore.getInstance("PKCS12");
        InputStream in = Files.newInputStream(path);
        try {
            store.load(in, password == null ? new char[0] : password.toCharArray());
        } finally {
            in.close();
        }
        return store;
    }
}
