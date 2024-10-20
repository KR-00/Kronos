import sys
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QLabel, QMessageBox, QInputDialog, QTextEdit, QHBoxLayout
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import Qt, QThread, Signal
from modules.route_mapper.crawler import start_crawler

# Worker class to handle the crawler in a separate thread
class CrawlerWorker(QThread):
    crawler_finished = Signal(list)  # Signal emitted when the crawler finishes, sending the result list

    def __init__(self, port):
        super().__init__()
        self.port = port

    def run(self):
        try:
            pages = []  # List to hold discovered pages
            pages = start_crawler(self.port)  # Capture the pages found
            self.crawler_finished.emit(pages)  # Emit the signal with the list of pages
        except Exception as e:
            self.crawler_finished.emit([f"An error occurred: {e}"])


class KronosApp(QWidget):
    def __init__(self):
        super().__init__()

        # Set up the main window
        self.setWindowTitle("Kronos")
        self.setGeometry(100, 100, 600, 400)
        self.setStyleSheet("background-color: #2c2c2c; color: #CD7F32;")  # Bronze text color

        # Set the application icon (make sure the icon file path is correct)
        self.setWindowIcon(QIcon("assets/kronos_logo.png"))  # Kronos logo as window icon

        # Create a layout
        layout = QVBoxLayout()

        # Add Kronos logo at the top of the window
        logo_label = QLabel(self)

        # Load and resize the Kronos logo
        logo_pixmap = QPixmap("assets/kronos_logo.png")
        resized_logo_pixmap = logo_pixmap.scaled(100, 100, Qt.KeepAspectRatio)  # Resize to 100x100 pixels

        logo_label.setPixmap(resized_logo_pixmap)  # Display the resized image
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)

        # Create a results text area
        self.results_box = QTextEdit(self)
        self.results_box.setReadOnly(True)
        self.results_box.setStyleSheet("background-color: #1e1e1e; color: #CD7F32; padding: 10px; font-size: 12px;")  # Bronze text color for results
        layout.addWidget(self.results_box)

        # Create the buttons
        button_layout = QHBoxLayout()

        run_button = QPushButton("Run Crawler")
        run_button.setStyleSheet("background-color: #1e1e1e; padding: 10px; font-size: 14px; color: #CD7F32;")  # Bronze text color for button
        run_button.clicked.connect(self.run_crawler)
        button_layout.addWidget(run_button)

        exit_button = QPushButton("Exit")
        exit_button.setStyleSheet("background-color: #1e1e1e; padding: 10px; font-size: 14px; color: #CD7F32;")  # Bronze text color for button
        exit_button.clicked.connect(self.confirm_exit)
        button_layout.addWidget(exit_button)

        layout.addLayout(button_layout)

        # Set the layout for the window
        self.setLayout(layout)

        self.crawler_thread = None  # Initialize crawler thread

    def run_crawler(self):
        # Ask the user for the port in a pop-up input dialog
        port, ok = QInputDialog.getText(self, "Input Port", "Please enter the port (default is 42000):")
        
        if ok:
            if port == "":  # If no port is entered, use the default
                port = 42000
            else:
                try:
                    port = int(port)  # Convert input to an integer
                except ValueError:
                    QMessageBox.critical(self, "Invalid Input", "The port must be a valid number.")
                    return

            # Start the crawler in a separate thread
            self.crawler_thread = CrawlerWorker(port)
            self.crawler_thread.crawler_finished.connect(self.show_crawler_result)
            self.results_box.clear()  # Clear previous results before running a new crawl
            self.results_box.append("Crawling started...")  # Notify the user that crawling has started
            self.crawler_thread.start()  # Start the thread

    def show_crawler_result(self, pages):
        # Display the results when the crawler finishes
        self.results_box.clear()  # Clear the text box
        if pages:
            for page in pages:
                self.results_box.append(page)  # Add each discovered page to the results box
        else:
            self.results_box.append("No pages found.")

    def confirm_exit(self):
        # Show a confirmation dialog before exiting, with no icon
        exit_message = QMessageBox(self)
        exit_message.setWindowTitle("Exit Confirmation")
        exit_message.setText("Do you really want to exit?")
        exit_message.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        exit_message.setDefaultButton(QMessageBox.No)
        exit_message.setIcon(QMessageBox.NoIcon)  # No icon for the dialog
        reply = exit_message.exec()

        if reply == QMessageBox.Yes:
            self.close()

    def closeEvent(self, event):
        # Gracefully stop the crawler thread if it is still running
        if self.crawler_thread and self.crawler_thread.isRunning():
            self.crawler_thread.terminate()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = KronosApp()
    window.show()

    sys.exit(app.exec())
