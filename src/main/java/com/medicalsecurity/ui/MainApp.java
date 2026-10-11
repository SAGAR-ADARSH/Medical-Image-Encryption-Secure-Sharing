package com.medicalsecurity.ui;

import javafx.application.Application;
import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.event.EventHandler;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

/**
 * JavaFX entry point: shows the login screen and, after authentication, the
 * role-specific main window (11 screens in total, navy/white theme).
 */
public final class MainApp extends Application {

    private static Stage primaryStage;

    @Override
    public void start(Stage stage) throws Exception {
        primaryStage = stage;
        AppContext.get(); // boot database + backend services before any UI work
        showLogin();
        stage.setTitle("Medical Image Encryption & Secure Sharing");
        stage.setMinWidth(1024);
        stage.setMinHeight(680);
        stage.setOnCloseRequest(new javafx.event.EventHandler() {
            @Override
            public void handle(javafx.event.Event event) {
                AppContext.get().close();
                Platform.exit();
            }
        });
        stage.show();
    }

    public static Stage getPrimaryStage() {
        return primaryStage;
    }

    /** Loads any screen from src/main/resources/fxml. */
    public static Parent loadScreen(String fxmlName) throws Exception {
        return (Parent) FXMLLoader.load(MainApp.class.getResource("/fxml/" + fxmlName));
    }

    public static void showScene(Parent root, String title) {
        Scene scene = new Scene(root, 1180, 760);
        scene.getStylesheets().add(MainApp.class.getResource("/css/styles.css").toExternalForm());
        primaryStage.setScene(scene);
        primaryStage.setTitle(title);
    }

    public static void showLogin() throws Exception {
        showScene(loadScreen("LoginScreen.fxml"),
                "Login - Medical Image Encryption & Secure Sharing");
    }

    /** Role-based main shell after a successful login. */
    public static void showMainShell() throws Exception {
        showScene(loadScreen("MainShell.fxml"),
                "Medical Image Encryption & Secure Sharing");
    }

    public static void main(String[] args) {
        launch(args);
    }
}
