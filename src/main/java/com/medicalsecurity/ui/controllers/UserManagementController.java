package com.medicalsecurity.ui.controllers;

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
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextField;
import javafx.scene.control.TableColumn.CellDataFeatures;
import javafx.util.Callback;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Callable;

/** User management controller (screen 7 of 11, ADMIN only). */
public final class UserManagementController {

    @FXML
    private TextField newUsernameField;
    @FXML
    private PasswordField newPasswordField;
    @FXML
    private TextField newFullNameField;
    @FXML
    private ComboBox<String> newRoleBox;
    @FXML
    private Button toggleButton;
    @FXML
    private Label infoLabel;
    @FXML
    private TableView<User> table;
    @FXML
    private TableColumn<User, String> colId;
    @FXML
    private TableColumn<User, String> colUsername;
    @FXML
    private TableColumn<User, String> colFullName;
    @FXML
    private TableColumn<User, String> colRole;
    @FXML
    private TableColumn<User, String> colActive;
    @FXML
    private TableColumn<User, String> colCreated;

    private final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm");

    @FXML
    private void initialize() {
        ObservableList<String> roles = FXCollections.observableArrayList();
        roles.add("DOCTOR");
        roles.add("SPECIALIST");
        roles.add("ADMIN");
        newRoleBox.setItems(roles);
        newRoleBox.setValue("SPECIALIST");
        colId.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) { return String.valueOf(u.getId()); }
        }));
        colUsername.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) { return u.getUsername(); }
        }));
        colFullName.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) { return u.getFullName(); }
        }));
        colRole.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) { return String.valueOf(u.getRole()); }
        }));
        colActive.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) { return u.isActive() ? "yes" : "no"; }
        }));
        colCreated.setCellValueFactory(textOf(new TextOf() {
            public String get(User u) {
                synchronized (format) {
                    return format.format(new Date(u.getCreatedAtMs()));
                }
            }
        }));
        handleRefresh();
    }

    private Callback textOf(final TextOf text) {
        return new Callback() {
            @Override
            public Object call(Object param) {
            CellDataFeatures<User, String> p = (CellDataFeatures<User, String>) param;
                return new SimpleStringProperty(text.get((User) p.getValue()));
            }
        };
    }

    private interface TextOf {
        String get(User u);
    }

    @FXML
    private void handleRefresh() {
        UiTasks.run("Loading users...", new Callable() {
            @Override
            public Object call() throws Exception {
                final List<User> users = AppContext.get().getUserAdminService()
                        .listUsers(currentUser());
                javafx.application.Platform.runLater(new Runnable() {
                    @Override
                    public void run() {
                        ObservableList<User> items = FXCollections.observableArrayList();
                        items.addAll(users);
                        table.setItems(items);
                        infoLabel.setText(users.size() + " account(s)");
                    }
                });
                return null;
            }
        }, null);
    }

    @FXML
    private void handleCreate(ActionEvent event) {
        final String username = newUsernameField.getText() == null ? "" : newUsernameField.getText().trim();
        final String password = newPasswordField.getText() == null ? "" : newPasswordField.getText();
        final String fullName = newFullNameField.getText() == null ? "" : newFullNameField.getText().trim();
        final String roleValue = newRoleBox.getValue() == null ? "SPECIALIST" : (String) newRoleBox.getValue();
        UiTasks.run("Creating user...", new Callable() {
            @Override
            public Object call() throws Exception {
                AppContext.get().getUserAdminService().createUser(currentUser(),
                        username, password, fullName, Role.fromString(roleValue), "127.0.0.1");
                return null;
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                newPasswordField.setText("");
                handleRefresh();
                UiTasks.showInfo("User created",
                        "Account '" + username + "' created with a new PKCS#12 keystore.");
            }
        });
    }

    @FXML
    private void handleToggle(ActionEvent event) {
        final User selected = (User) table.getSelectionModel().getSelectedItem();
        if (selected == null) {
            infoLabel.setText("Select an account first.");
            return;
        }
        UiTasks.run("Updating account...", new Callable() {
            @Override
            public Object call() throws Exception {
                AppContext.get().getUserAdminService().setActive(currentUser(),
                        selected.getId(), !selected.isActive(), "127.0.0.1");
                return null;
            }
        }, new UiTasks.Success() {
            @Override
            public void accept(Object value) {
                handleRefresh();
            }
        });
    }

    private User currentUser() {
        return AppContext.get().getAuthService().requireFreshUser(
                AppContext.get().getCurrentSession());
    }
}
