package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.User;
import com.medicalsecurity.model.UserSession;
import com.medicalsecurity.service.PreparedTransfer;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.File;
import java.security.PublicKey;
import java.util.List;
import java.util.concurrent.Callable;

/** Send-image controller: encrypt + wrap + submit (screen 3 of 11). */
public final class SendImageController {

    @FXML
    private TextField filePathField;
    @FXML
    private ComboBox<User> recipientBox;
    @FXML
    private Button sendButton;
    @FXML
    private ProgressBar progressBar;
    @FXML
    private Label resultLabel;

    private File selectedFile;

    @FXML
    private void initialize() {
        handleRefresh();
    }

    @FXML
    private void handleBrowse(ActionEvent event) {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Select medical image");
        chooser.getExtensionFilters().add(
                new FileChooser.ExtensionFilter("Images", "*.png", "*.jpg", "*.jpeg", "*.bmp"));
        File file = chooser.showOpenDialog(MainAppHolder.stage());
        if (file != null) {
            selectedFile = file;
            filePathField.setText(file.getAbsolutePath());
        }
    }

    @FXML
    private void handleRefresh(ActionEvent event) {
        UiTasks.run("Loading recipients...", new Callable() {
            @Override
            public Object call() throws Exception {
                final List<User> recipients =
                        AppContext.get().getUserAdminService().listRecipients(currentUser());
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<User> items = FXCollections.observableArrayList();
                        items.addAll(recipients);
                        recipientBox.setItems(items);
                    }
                });
                return null;
            }
        }, null);
    }

    /** Convenience for the no-arg initialize() call. */
    private void handleRefresh() {
        handleRefresh(null);
    }

    @FXML
    private void handleSend(ActionEvent event) {
        final User recipient = (User) recipientBox.getValue();
        if (selectedFile == null || recipient == null) {
            resultLabel.setText("Choose an image file and a recipient first.");
            return;
        }
        sendButton.setDisable(true);
        progressBar.setProgress(-1);
        resultLabel.setText("Encrypting and sending...");
        UiTasks.run("Encrypting...", new Callable() {
            @Override
            public Object call() throws Exception {
                User sender = currentUser();
                SenderSend.send(sender, recipient, selectedFile);
                return "Transfer sent to " + recipient.getUsername() + ".";
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                progressBar.setProgress(1);
                resultLabel.setText((String) value);
                sendButton.setDisable(false);
            }
        });
    }

    private User currentUser() {
        UserSession session = AppContext.get().getCurrentSession();
        return AppContext.get().getAuthService().requireFreshUser(session);
    }

    /** Encapsulates the sender-side backend calls (background thread). */
    private static final class SenderSend {
        static void send(User sender, User recipient, File file) throws Exception {
            byte[] imageBytes = AppContext.get().getSenderEncryptionService()
                    .readImageFile(file.toPath());
            PublicKey recipientPublic = com.medicalsecurity.crypto.KeystoreService.publicKeyFromDer(
                    AppContext.get().getKeyManagementService()
                            .getPublicKey(sender, recipient.getUsername()).publicKeyDer);
            PreparedTransfer prepared = AppContext.get().getSenderEncryptionService()
                    .prepareOutgoing(sender, recipient, file.getName(), imageBytes, recipientPublic);
            AppContext.get().getTransferService().receiveIncoming(sender, prepared.getManifest(),
                    prepared.getWrappedKey(), prepared.getCiphertext());
        }
    }

    /** Small holder to reach the primary stage without a circular import. */
    static final class MainAppHolder {
        static javafx.stage.Stage stage() {
            return com.medicalsecurity.ui.MainApp.getPrimaryStage();
        }
    }
}
