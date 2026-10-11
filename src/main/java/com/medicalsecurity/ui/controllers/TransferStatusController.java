package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.Role;
import com.medicalsecurity.model.User;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.value.ObservableValue;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TableColumn.CellDataFeatures;
import javafx.util.Callback;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

/** Transfer history/status controller (screen 10 of 11). */
public final class TransferStatusController {

    @FXML
    private TableView<ImageTransfer> table;
    @FXML
    private TableColumn<ImageTransfer, String> colId;
    @FXML
    private TableColumn<ImageTransfer, String> colSender;
    @FXML
    private TableColumn<ImageTransfer, String> colRecipient;
    @FXML
    private TableColumn<ImageTransfer, String> colFile;
    @FXML
    private TableColumn<ImageTransfer, String> colPlain;
    @FXML
    private TableColumn<ImageTransfer, String> colCipher;
    @FXML
    private TableColumn<ImageTransfer, String> colStatus;
    @FXML
    private TableColumn<ImageTransfer, String> colUpdated;
    @FXML
    private Label infoLabel;

    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    @FXML
    private void initialize() {
        colId.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return t.getTransferId(); }
        }));
        colSender.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getSenderId()); }
        }));
        colRecipient.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getRecipientId()); }
        }));
        colFile.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return t.getOriginalFilename(); }
        }));
        colPlain.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getPlaintextSize()); }
        }));
        colCipher.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getCiphertextSize()); }
        }));
        colStatus.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getStatus()); }
        }));
        colUpdated.setCellValueFactory(textOf(new TextOf() {
            public String get(ImageTransfer t) {
                synchronized (format) {
                    return format.format(new Date(t.getUpdatedAtMs()));
                }
            }
        }));
        handleRefresh();
    }

    private Callback textOf(final TextOf text) {
        return new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(text.get((ImageTransfer) p.getValue()));
            }
        };
    }

    private interface TextOf {
        String get(ImageTransfer t);
    }

    private void handleRefresh() {
        handleRefresh(null);
    }

    @FXML
    private void handleRefresh(ActionEvent event) {
        UiTasks.run("Loading transfers...", new Callable() {
            @Override
            public Object call() throws Exception {
                User user = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                final List<ImageTransfer> rows;
                if (user.getRole() == Role.ADMIN) {
                    rows = AppContext.get().getTransferService().listAll(user, 200);
                } else if (user.getRole().canSendTransfers()) {
                    rows = AppContext.get().getTransferService().listOutgoing(user);
                } else {
                    rows = AppContext.get().getTransferService().listIncoming(user);
                }
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<ImageTransfer> items = FXCollections.observableArrayList();
                        items.addAll(rows);
                        table.setItems(items);
                        infoLabel.setText(rows.size() + " transfer(s)");
                    }
                });
                return null;
            }
        }, null);
    }
}
