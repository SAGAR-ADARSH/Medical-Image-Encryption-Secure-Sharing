package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.MainApp;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Parent;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

/** Main shell controller: role-aware side navigation (screens 2-11). */
public final class MainShellController {

    @FXML
    private VBox sideNav;
    @FXML
    private StackPane contentPane;
    @FXML
    private Label userLabel;
    @FXML
    private Label statusLabel;
    @FXML
    private Button navDashboard;
    @FXML
    private Button navSend;
    @FXML
    private Button navOutbox;
    @FXML
    private Button navInbox;
    @FXML
    private Button navVerify;
    @FXML
    private Button navStatus;
    @FXML
    private Button navUsers;
    @FXML
    private Button navKeys;
    @FXML
    private Button navAudit;
    @FXML
    private Button navSettings;

    @FXML
    private void initialize() {
        UserSession session = AppContext.get().getCurrentSession();
        if (session == null) {
            return;
        }
        Role role = session.getRole();
        userLabel.setText(session.getUsername() + " (" + role + ")");
        // Server-side RBAC is enforced in every service call; the visibility
        // rules below are purely usability.
        navSend.setVisible(role.canSendTransfers());
        navSend.setManaged(role.canSendTransfers());
        navOutbox.setVisible(role.canSendTransfers());
        navOutbox.setManaged(role.canSendTransfers());
        navInbox.setVisible(role.canReceiveTransfers());
        navInbox.setManaged(role.canReceiveTransfers());
        navVerify.setVisible(role.canReceiveTransfers());
        navVerify.setManaged(role.canReceiveTransfers());
        navUsers.setVisible(role.isAdmin());
        navUsers.setManaged(role.isAdmin());
        navAudit.setVisible(role.isAdmin());
        navAudit.setManaged(role.isAdmin());
        showDashboard();
    }

    private void show(String fxmlName, String status) {
        try {
            Parent screen = MainApp.loadScreen(fxmlName);
            contentPane.getChildren().clear();
            contentPane.getChildren().add(screen);
            statusLabel.setText(status);
        } catch (Exception e) {
            UiTasksLocal.showError("Cannot load screen", e);
        }
    }

    @FXML
    private void showDashboard() {
        show("DashboardScreen.fxml", "Dashboard");
    }

    @FXML
    private void showSend(ActionEvent event) {
        show("SendImageScreen.fxml", "Encrypt and send an image");
    }

    @FXML
    private void showOutbox(ActionEvent event) {
        show("OutboxScreen.fxml", "Sent transfers");
    }

    @FXML
    private void showInbox(ActionEvent event) {
        show("InboxScreen.fxml", "Incoming transfers");
    }

    @FXML
    private void showVerify(ActionEvent event) {
        show("VerifyDecryptScreen.fxml", "Verify and decrypt");
    }

    @FXML
    private void showStatus(ActionEvent event) {
        show("TransferStatusScreen.fxml", "Transfer history");
    }

    @FXML
    private void showUsers(ActionEvent event) {
        show("UserManagementScreen.fxml", "User management");
    }

    @FXML
    private void showKeys(ActionEvent event) {
        show("KeyManagementScreen.fxml", "Key management");
    }

    @FXML
    private void showAudit(ActionEvent event) {
        show("AuditLogScreen.fxml", "Audit log");
    }

    @FXML
    private void showSettings(ActionEvent event) {
        show("SettingsScreen.fxml", "Settings");
    }

    @FXML
    private void handleLogout(ActionEvent event) {
        try {
            UserSession session = AppContext.get().getCurrentSession();
            if (session != null) {
                AppContext.get().getAuthService().logout(session.getToken(), "127.0.0.1");
            }
            AppContext.get().setCurrentSession(null);
            MainApp.showLogin();
        } catch (Exception e) {
            UiTasksLocal.showError("Logout failed", e);
        }
    }

    /** Local alias to avoid an import cycle in stub compilation. */
    private static final class UiTasksLocal {
        static void showError(String title, Throwable error) {
            com.medicalsecurity.ui.UiTasks.showError(title, error);
        }
    }
}
