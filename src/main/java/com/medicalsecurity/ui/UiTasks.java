package com.medicalsecurity.ui;

import javafx.concurrent.Task;
import javafx.event.EventHandler;
import javafx.scene.control.Alert;

/**
 * Background-task helper: every blocking operation (database, crypto, disk,
 * sockets) runs on a JavaFX {@link Task} worker thread so the UI thread never
 * freezes (spec requirement). Failures are shown honestly - no fake success
 * notifications.
 */
public final class UiTasks {

    private UiTasks() {
    }

    /** Runs work off the FX thread; calls onDone(result) or shows the error. */
    @SuppressWarnings("unchecked")
    public static void run(String busyMessage, final java.util.concurrent.Callable work,
                           final Success onDone) {
        final Task task = new Task() {
            @Override
            protected Object call() throws Exception {
                return work.call();
            }
        };
        task.setOnSucceeded(new EventHandler() {
            @Override
            public void handle(javafx.event.Event event) {
                try {
                    onDone.accept(task.getValue());
                } catch (Exception e) {
                    showError("Operation failed", e);
                }
            }
        });
        task.setOnFailed(new EventHandler() {
            @Override
            public void handle(javafx.event.Event event) {
                showError("Operation failed", task.getException());
            }
        });
        Thread worker = new Thread(task, "medsec-worker");
        worker.setDaemon(true);
        worker.start();
    }

    /** Runs work off the FX thread without a result. */
    public static void runVoid(String busyMessage, java.util.concurrent.Callable work,
                               final Runnable onDone) {
        run(busyMessage, work, new Success() {
            @Override
            public void accept(Object value) throws Exception {
                if (onDone != null) {
                    onDone.run();
                }
            }
        });
    }

    public static void showError(String title, Throwable error) {
        String message = error == null ? "Unknown error" : String.valueOf(error.getMessage());
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void showInfo(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public static void showWarning(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.WARNING);
        alert.setTitle(title);
        alert.setHeaderText(title);
        alert.setContentText(message);
        alert.showAndWait();
    }

    public interface Success {
        void accept(Object value) throws Exception;
    }
}
