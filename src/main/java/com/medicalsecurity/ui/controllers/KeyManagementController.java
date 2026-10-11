package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.dao.PublicKeyRecord;
import com.medicalsecurity.model.User;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.control.TableColumn.CellDataFeatures;
import javafx.util.Callback;

import java.security.MessageDigest;
import java.util.List;
import java.util.concurrent.Callable;

/** Key-management controller (screen 9 of 11). */
public final class KeyManagementController {

    @FXML
    private TableView<PublicKeyRecord> table;
    @FXML
    private TableColumn<PublicKeyRecord, String> colUser;
    @FXML
    private TableColumn<PublicKeyRecord, String> colAlg;
    @FXML
    private TableColumn<PublicKeyRecord, String> colBits;
    @FXML
    private TableColumn<PublicKeyRecord, String> colVersion;
    @FXML
    private TableColumn<PublicKeyRecord, String> colFingerprint;
    @FXML
    private Button provisionButton;
    @FXML
    private Label infoLabel;
    @FXML
    private TextArea detailArea;

    @FXML
    private void initialize() {
        colUser.setCellValueFactory(textOf(new TextOf() {
            public String get(PublicKeyRecord r) { return r.username; }
        }));
        colAlg.setCellValueFactory(textOf(new TextOf() {
            public String get(PublicKeyRecord r) { return r.algorithm; }
        }));
        colBits.setCellValueFactory(textOf(new TextOf() {
            public String get(PublicKeyRecord r) { return String.valueOf(r.keySizeBits); }
        }));
        colVersion.setCellValueFactory(textOf(new TextOf() {
            public String get(PublicKeyRecord r) { return String.valueOf(r.keyVersion); }
        }));
        colFingerprint.setCellValueFactory(textOf(new TextOf() {
            public String get(PublicKeyRecord r) { return fingerprint(r.publicKeyDer); }
        }));
        table.getSelectionModel().selectedItemProperty().addListener(
                new javafx.beans.value.ChangeListener() {
                    @Override
                    public void changed(ObservableValue observable,
                                        Object oldValue, Object newValue) {
                        PublicKeyRecord record = (PublicKeyRecord) newValue;
                        if (record != null) {
                            detailArea.setText("User       : " + record.username
                                    + "\nAlgorithm  : " + record.algorithm
                                    + "\nKey size   : " + record.keySizeBits + " bits"
                                    + "\nVersion    : " + record.keyVersion
                                    + "\nDER bytes  : " + record.publicKeyDer.length
                                    + "\nFingerprint: " + fingerprint(record.publicKeyDer));
                        }
                    }
                });
        handleRefresh();
    }

    private Callback textOf(final TextOf text) {
        return new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<PublicKeyRecord, String> p = (CellDataFeatures<PublicKeyRecord, String>) param;
                return new SimpleStringProperty(text.get((PublicKeyRecord) p.getValue()));
            }
        };
    }

    private interface TextOf {
        String get(PublicKeyRecord r);
    }

    static String fingerprint(byte[] der) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(der);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hash.length; i++) {
                sb.append(String.format("%02X", hash[i]));
                if (i < hash.length - 1) {
                    sb.append(':');
                }
            }
            return sb.toString();
        } catch (Exception e) {
            return "(unavailable)";
        }
    }

    private void handleRefresh() {
        handleRefresh(null);
    }

    @FXML
    private void handleRefresh(ActionEvent event) {
        UiTasks.run("Loading keys...", new Callable() {
            @Override
            public Object call() throws Exception {
                User admin = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                List<User> users = AppContext.get().getDaos().users().findAll();
                final java.util.List<PublicKeyRecord> rows = new java.util.ArrayList<PublicKeyRecord>();
                for (int i = 0; i < users.size(); i++) {
                    User u = (User) users.get(i);
                    PublicKeyRecord record =
                            AppContext.get().getDaos().publicKeys().findLatestByUsername(u.getUsername());
                    if (record != null) {
                        rows.add(record);
                    }
                }
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<PublicKeyRecord> items = FXCollections.observableArrayList();
                        items.addAll(rows);
                        table.setItems(items);
                        infoLabel.setText(rows.size() + " public key record(s)");
                    }
                });
                return null;
            }
        }, null);
    }

    @FXML
    private void handleProvision(ActionEvent event) {
        UiTasks.run("Provisioning keys...", new Callable() {
            @Override
            public Object call() throws Exception {
                User admin = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                com.medicalsecurity.security.AuthorizationService.requireAdmin(admin);
                List<User> users = AppContext.get().getDaos().users().findAll();
                int created = 0;
                for (int i = 0; i < users.size(); i++) {
                    User u = (User) users.get(i);
                    if (!AppContext.get().getKeystoreService().hasKeyStore(u.getUsername())) {
                        java.security.PublicKey pub = AppContext.get().getKeystoreService()
                                .provisionKeyPair(u.getUsername());
                        AppContext.get().getKeyManagementService().registerUserPublicKey(
                                u.getId(), u.getUsername(), "RSA",
                                com.medicalsecurity.crypto.KeystoreService.KEY_SIZE_BITS,
                                pub.getEncoded(), 1, u.getUsername() + ".p12");
                        created++;
                    }
                }
                return created + " keystore(s) provisioned.";
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                handleRefresh();
                UiTasks.showInfo("Key provisioning", (String) value);
            }
        });
    }
}
