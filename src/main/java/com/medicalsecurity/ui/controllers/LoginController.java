package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.MainApp;
import com.medicalsecurity.ui.UiTasks;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;

import java.util.concurrent.Callable;

/** Login screen controller (screen 1 of 11). */
public final class LoginController {

    @FXML
    private TextField usernameField;
    @FXML
    private PasswordField passwordField;
    @FXML
    private Label statusLabel;
    @FXML
    private Button loginButton;

    @FXML
    private void handleLogin(ActionEvent event) {
        final String username = usernameField.getText() == null ? "" : usernameField.getText().trim();
        final String password = passwordField.getText() == null ? "" : passwordField.getText();
        statusLabel.setText("Signing in...");
        loginButton.setDisable(true);
        UiTasks.run("Signing in...", new Callable() {
            @Override
            public Object call() throws Exception {
                UserSession session = AppContext.get().getAuthService()
                        .login(username, password.toCharArray(), "127.0.0.1");
                AppContext.get().setCurrentSession(session);
                return null;
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) throws Exception {
                MainApp.showMainShell();
            }
        });
        loginButton.setDisable(false);
    }
}
