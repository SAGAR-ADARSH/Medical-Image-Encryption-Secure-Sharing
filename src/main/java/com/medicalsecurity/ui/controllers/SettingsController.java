package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.ui.AppContext;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;

/** Settings controller (screen 11 of 11). */
public final class SettingsController {

    @FXML
    private TextArea configArea;
    @FXML
    private Label backendLabel;

    @FXML
    private void initialize() {
        configArea.setText(AppContext.get().getConfig().describe());
        backendLabel.setText(
                "Key-management service : " + AppContext.get().getConfig().getServerHost()
                        + ":" + AppContext.get().getConfig().getKeyManagerPort() + "\n"
                        + "Transfer service       : " + AppContext.get().getConfig().getServerHost()
                        + ":" + AppContext.get().getConfig().getTransferPort() + "\n"
                        + "TLS                    : " + (AppContext.get().getConfig().isTlsEnabled()
                        ? "enabled" : "disabled (localhost demo)") + "\n"
                        + "The in-process backend is running while the application is open; "
                        + "a standalone instance can be started with com.medicalsecurity.network.BackendServer.");
    }
}
