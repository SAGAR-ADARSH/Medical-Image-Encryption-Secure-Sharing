package com.medicalsecurity.ui.controllers;

import com.medicalsecurity.model.AuditEvent;
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

/** Audit-log controller (screen 8 of 11, ADMIN only). */
public final class AuditLogController {

    @FXML
    private TableView<AuditEvent> table;
    @FXML
    private TableColumn<AuditEvent, String> colTime;
    @FXML
    private TableColumn<AuditEvent, String> colType;
    @FXML
    private TableColumn<AuditEvent, String> colUser;
    @FXML
    private TableColumn<AuditEvent, String> colOutcome;
    @FXML
    private TableColumn<AuditEvent, String> colDetail;
    @FXML
    private TableColumn<AuditEvent, String> colIp;
    @FXML
    private Label infoLabel;

    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    @FXML
    private void initialize() {
        colTime.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) {
                synchronized (format) {
                    return format.format(new Date(e.getCreatedAtMs()));
                }
            }
        }));
        colType.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) { return e.getEventType(); }
        }));
        colUser.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) { return e.getUsername() == null ? "-" : e.getUsername(); }
        }));
        colOutcome.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) { return e.getOutcome(); }
        }));
        colDetail.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) { return e.getDetail() == null ? "" : e.getDetail(); }
        }));
        colIp.setCellValueFactory(textOf(new TextOf() {
            public String get(AuditEvent e) { return e.getSourceIp() == null ? "-" : e.getSourceIp(); }
        }));
        handleRefresh();
    }

    private Callback textOf(final TextOf text) {
        return new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<AuditEvent, String> p = (CellDataFeatures<AuditEvent, String>) param;
                return new SimpleStringProperty(text.get((AuditEvent) p.getValue()));
            }
        };
    }

    private interface TextOf {
        String get(AuditEvent e);
    }

    private void handleRefresh() {
        handleRefresh(null);
    }

    @FXML
    private void handleRefresh(ActionEvent event) {
        UiTasks.run("Loading audit log...", new Callable() {
            @Override
            public Object call() throws Exception {
                User admin = AppContext.get().getAuthService().requireFreshUser(
                        AppContext.get().getCurrentSession());
                com.medicalsecurity.security.AuthorizationService.requireAdmin(admin);
                final List<AuditEvent> rows = AppContext.get().getAuditLogDAO().findRecent(200);
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<AuditEvent> items = FXCollections.observableArrayList();
                        items.addAll(rows);
                        table.setItems(items);
                        infoLabel.setText(rows.size() + " event(s)");
                    }
                });
                return null;
            }
        }, null);
    }
}
