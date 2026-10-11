package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.ImageTransfer;
import com.medicalsecurity.model.User;
import com.medicalsecurity.ui.AppContext;
import com.medicalsecurity.ui.UiTasks;
import javafx.beans.property.SimpleStringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.util.Callback;
import javafx.scene.control.TableColumn.CellDataFeatures;
import javafx.beans.value.ObservableValue;

import java.text.SimpleDateFormat;
import java.util.List;
import java.util.concurrent.Callable;

/** Outbox controller (screen 4 of 11). */
public final class OutboxController {

    @FXML
    private TableView<ImageTransfer> table;
    @FXML
    private TableColumn<ImageTransfer, String> colId;
    @FXML
    private TableColumn<ImageTransfer, String> colRecipient;
    @FXML
    private TableColumn<ImageTransfer, String> colFile;
    @FXML
    private TableColumn<ImageTransfer, String> colSize;
    @FXML
    private TableColumn<ImageTransfer, String> colStatus;
    @FXML
    private TableColumn<ImageTransfer, String> colCreated;
    @FXML
    private Label infoLabel;

    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    @FXML
    private void initialize() {
        colId.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(((ImageTransfer) p.getValue()).getTransferId());
            }
        });
        colRecipient.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(String.valueOf(((ImageTransfer) p.getValue()).getRecipientId()));
            }
        });
        colFile.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(((ImageTransfer) p.getValue()).getOriginalFilename());
            }
        });
        colSize.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(String.valueOf(((ImageTransfer) p.getValue()).getCiphertextSize()));
            }
        });
        colStatus.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                return new SimpleStringProperty(String.valueOf(((ImageTransfer) p.getValue()).getStatus()));
            }
        });
        colCreated.setCellValueFactory(new Callback() {
            @Override
            public Object call(Object param) {
                CellDataFeatures<ImageTransfer, String> p = (CellDataFeatures<ImageTransfer, String>) param;
                synchronized (format) {
                    return new SimpleStringProperty(format.format(new java.util.Date(((ImageTransfer) p.getValue()).getCreatedAtMs())));
                }
            }
        });
        handleRefresh();
    }

    private void handleRefresh() {
        handleRefresh(null);
    }

    @FXML
    private void handleRefresh(ActionEvent event) {
        UiTasks.run("Loading outbox...", new Callable() {
            @Override
            public Object call() throws Exception {
                User sender = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                final List<ImageTransfer> rows =
                        AppContext.get().getTransferService().listOutgoing(sender);
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
