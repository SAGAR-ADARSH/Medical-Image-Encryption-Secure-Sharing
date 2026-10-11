package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.TransferStatus;
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

/** Inbox controller (screen 5 of 11). */
public final class InboxController {

    @FXML
    private TableView<ImageTransfer> table;
    @FXML
    private TableColumn<ImageTransfer, String> colId;
    @FXML
    private TableColumn<ImageTransfer, String> colFile;
    @FXML
    private TableColumn<ImageTransfer, String> colSize;
    @FXML
    private TableColumn<ImageTransfer, String> colStatus;
    @FXML
    private TableColumn<ImageTransfer, String> colReceived;
    @FXML
    private Label infoLabel;

    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    @FXML
    private void initialize() {
        colId.setCellValueFactory(stringCell(new TextOf() {
            public String get(ImageTransfer t) { return t.getTransferId(); }
        }));
        colFile.setCellValueFactory(stringCell(new TextOf() {
            public String get(ImageTransfer t) { return t.getOriginalFilename(); }
        }));
        colSize.setCellValueFactory(stringCell(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getCiphertextSize()); }
        }));
        colStatus.setCellValueFactory(stringCell(new TextOf() {
            public String get(ImageTransfer t) { return String.valueOf(t.getStatus()); }
        }));
        colReceived.setCellValueFactory(stringCell(new TextOf() {
            public String get(ImageTransfer t) {
                Long received = t.getReceivedAtMs();
                synchronized (format) {
                    return received == null ? "-" : format.format(new Date(received.longValue()));
                }
            }
        }));
        handleRefresh();
    }

    private Callback stringCell(final TextOf text) {
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
        UiTasks.run("Loading inbox...", new Callable() {
            @Override
            public Object call() throws Exception {
                User recipient = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                final List<ImageTransfer> rows =
                        AppContext.get().getTransferService().listIncoming(recipient);
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

    @FXML
    private void handleReject(ActionEvent event) {
        final ImageTransfer selected = (ImageTransfer) table.getSelectionModel().getSelectedItem();
        if (selected == null) {
            infoLabel.setText("Select a transfer first.");
            return;
        }
        UiTasks.run("Rejecting...", new Callable() {
            @Override
            public Object call() throws Exception {
                User recipient = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                AppContext.get().getTransferService().rejectTransfer(recipient,
                        selected.getTransferId(), "Rejected by recipient", "127.0.0.1");
                return null;
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                handleRefresh();
                UiTasks.showInfo("Transfer rejected",
                        "Transfer " + selected.getTransferId() + " was rejected.");
            }
        });
    }
}
