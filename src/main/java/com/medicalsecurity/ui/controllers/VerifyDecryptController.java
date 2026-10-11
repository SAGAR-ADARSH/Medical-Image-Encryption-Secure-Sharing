package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.ProtectedKeyMaterial;
import com.medicalsecurity.model.User;
import com.medicalsecurity.service.DecryptionResult;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;

import java.io.File;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.util.concurrent.Callable;

/** Verify &amp; decrypt controller (screen 6 of 11). */
public final class VerifyDecryptController {

    @FXML
    private TextField transferIdField;
    @FXML
    private Button verifyButton;
    @FXML
    private Button decryptButton;
    @FXML
    private Label statusLabel;
    @FXML
    private TextArea detailArea;

    @FXML
    private void handleLoad(ActionEvent event) {
        final String transferId = text(transferIdField);
        UiTasks.run("Loading transfer...", new Callable() {
            @Override
            public Object call() throws Exception {
                User recipient = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                ImageTransfer t = AppContext.get().getTransferService()
                        .findTransfer(recipient, transferId);
                return "Transfer " + t.getTransferId()
                        + "\nFile     : " + t.getOriginalFilename()
                        + "\nSender   : user #" + t.getSenderId()
                        + "\nStatus   : " + t.getStatus()
                        + "\nSize     : " + t.getPlaintextSize() + " -> " + t.getCiphertextSize() + " bytes"
                        + "\nSHA-256  : " + t.getPlaintextSha256()
                        + "\nAlgorithm: " + t.getAlgorithm() + " " + t.getKeySizeBits() + " bits, tag "
                        + t.getTagBits() + " bits";
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                detailArea.setText((String) value);
                statusLabel.setText("Transfer loaded.");
            }
        });
    }

    @FXML
    private void handleVerify(ActionEvent event) {
        runDecryption(false);
    }

    @FXML
    private void handleDecrypt(ActionEvent event) {
        runDecryption(true);
    }

    private void runDecryption(final boolean saveToFile) {
        final String transferId = text(transferIdField);
        final File target;
        if (saveToFile) {
            FileChooser chooser = new FileChooser();
            chooser.setTitle("Save decrypted image");
            chooser.setInitialFileName("recovered-image.png");
            target = chooser.showSaveDialog(com.medicalsecurity.ui.MainApp.getPrimaryStage());
            if (target == null) {
                return;
            }
        } else {
            target = null;
        }
        statusLabel.setText("Verifying and decrypting...");
        UiTasks.run("Decrypting...", new Callable() {
            @Override
            public Object call() throws Exception {
                User recipient = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                ImageTransfer transfer = AppContext.get().getTransferService()
                        .findTransfer(recipient, transferId);
                byte[] ciphertext = AppContext.get().getTransferService()
                        .downloadPayload(recipient, transferId);
                ProtectedKeyMaterial released = AppContext.get().getKeyManagementService()
                        .releaseWrappedKey(recipient, transferId, "127.0.0.1");
                PrivateKey privateKey = AppContext.get().getKeystoreService()
                        .loadPrivateKey(recipient.getUsername());
                DecryptionResult result = AppContext.get().getReceiverDecryptionService()
                        .decryptIncoming(recipient, transfer, released.getWrappedKey(),
                                ciphertext, privateKey);
                StringBuilder sb = new StringBuilder();
                sb.append("GCM tag verified    : ").append(result.isGcmAuthenticated()).append('\n');
                sb.append("SHA-256 matches     : ").append(result.isHashMatches()).append('\n');
                sb.append("Recomputed SHA-256  : ").append(result.getPlaintextSha256()).append('\n');
                sb.append("Recovered bytes     : ").append(result.getRecoveredPlaintext().length).append('\n');
                if (saveToFile) {
                    Files.write(target.toPath(), result.getRecoveredPlaintext());
                    sb.append("Saved to            : ").append(target.getAbsolutePath()).append('\n');
                }
                // Advance the transfer state machine: VERIFIED then DECRYPTED.
                com.medicalsecurity.model.TransferStatus current = transfer.getStatus();
                if (current == com.medicalsecurity.model.TransferStatus.RECEIVED) {
                    AppContext.get().getTransferService().markStatus(recipient, transferId,
                            com.medicalsecurity.model.TransferStatus.VERIFIED, null, "127.0.0.1");
                }
                AppContext.get().getTransferService().markStatus(recipient, transferId,
                        com.medicalsecurity.model.TransferStatus.DECRYPTED, null, "127.0.0.1");
                return sb.toString();
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                statusLabel.setText(saveToFile
                        ? "Decryption successful - exact original bytes written."
                        : "Integrity verified - decryption would succeed.");
                detailArea.setText((String) value);
            }
        });
    }

    private static String text(TextField field) {
        return field.getText() == null ? "" : field.getText().trim();
    }
}
