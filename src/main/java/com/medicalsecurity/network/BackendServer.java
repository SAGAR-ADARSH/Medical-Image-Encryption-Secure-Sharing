package com.medicalsecurity.network;

import com.medicalsecurity.config.AppConfig;

import java.io.IOException;
import java.net.ServerSocket;

/**
 * Backend entry point: starts the KEY-MANAGEMENT service and the
 * TRANSFER-RECEIVING service in one process (they can be split into two
 * processes later without code changes - each is an independent listener).
 *
 * <p>Run: {@code mvn exec:java -Dexec.mainClass=com.medicalsecurity.network.BackendServer}
 * or {@code java -cp ... com.medicalsecurity.network.BackendServer}.
 *
 * <p>Startup fails fast when the database is unreachable, so a broken
 * deployment is detected immediately instead of at the first login.
 */
public final class BackendServer {

    private final ServerContext context;
    private ServerSocket keyManagerSocket;
    private ServerSocket transferSocket;
    private KeyManagementServer keyManagementServer;
    private TransferServer transferServer;

    public BackendServer(AppConfig config) {
        this.context = new ServerContext(config);
    }

    public void start() throws IOException {
        if (!context.database.isReachable()) {
            throw new IOException("Database is unreachable - check MEDSEC_DB_URL and that MySQL is running "
                    + "(or that the demo database was initialised)");
        }
        keyManagerSocket = SslSupport.createServerSocket(context.config, context.config.getKeyManagerPort());
        transferSocket = SslSupport.createServerSocket(context.config, context.config.getTransferPort());
        keyManagementServer = new KeyManagementServer(context, keyManagerSocket);
        transferServer = new TransferServer(context, transferSocket);
        keyManagementServer.start();
        transferServer.start();
        System.out.println("[backend] key-management service on port " + context.config.getKeyManagerPort());
        System.out.println("[backend] transfer service on port " + context.config.getTransferPort());
        System.out.println("[backend] TLS: " + (context.config.isTlsEnabled() ? "enabled" : "disabled (localhost demo)"));
    }

    public void stop() {
        try {
            if (keyManagerSocket != null) {
                keyManagerSocket.close();
            }
        } catch (IOException ignored) {
            // best effort
        }
        try {
            if (transferSocket != null) {
                transferSocket.close();
            }
        } catch (IOException ignored) {
            // best effort
        }
    }

    public ServerContext getContext() {
        return context;
    }

    public static void main(String[] args) throws Exception {
        final AppConfig config = AppConfig.load();
        final BackendServer server = new BackendServer(config);
        Runtime.getRuntime().addShutdownHook(new Thread(new Runnable() {
            @Override
            public void run() {
                server.stop();
            }
        }));
        server.start();
        System.out.println("[backend] ready. Press Ctrl+C to stop.");
        // Block the main thread.
        Thread.currentThread().join();
    }
}
