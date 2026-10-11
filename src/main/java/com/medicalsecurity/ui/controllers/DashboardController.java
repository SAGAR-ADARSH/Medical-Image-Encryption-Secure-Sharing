package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.fxml.FXML;
import javafx.scene.control.Label;

import java.util.List;
import java.util.concurrent.Callable;

/** Dashboard controller (screen 2 of 11). */
public final class DashboardController {

    @FXML
    private Label welcomeLabel;
    @FXML
    private Label inboxCount;
    @FXML
    private Label outboxCount;
    @FXML
    private Label userCount;
    @FXML
    private Label auditCount;

    @FXML
    private void initialize() {
        final UserSession session = AppContext.get().getCurrentSession();
        welcomeLabel.setText("Welcome, " + session.getUsername() + " (" + session.getRole() + ")");
        UiTasks.run("Loading dashboard...", new Callable() {
            @Override
            public Object call() throws Exception {
                final com.medicalsecurity.model.User user =
                        AppContext.get().getAuthService().requireFreshUser(session);
                final List<ImageTransfer> incoming =
                        AppContext.get().getTransferService().listIncoming(user);
                final List<ImageTransfer> outgoing =
                        AppContext.get().getTransferService().listOutgoing(user);
                final int users = AppContext.get().getDaos().users().findAll().size();
                final int audit = AppContext.get().getAuditLogDAO().findRecent(500).size();
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        inboxCount.setText(String.valueOf(incoming.size()));
                        outboxCount.setText(String.valueOf(outgoing.size()));
                        userCount.setText(String.valueOf(users));
                        auditCount.setText(String.valueOf(audit));
                    }
                });
                return null;
            }
        }, null);
    }
}
