# Networking Final Project
# Chris Keiningham

# Client program: Act as a user and participant in an IM chat room. The user can send and receive messages.

# Uses both a GUI and threads to handle the interface and constant message receiving with a worker thread.

import socket
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget
from PyQt5.QtCore import pyqtSignal
import rsa      # For encrypting and decrypting messages, use pip install rsa
import re

class Client(QWidget):    
    # Signal is used to update the GUI from the worker thread
    message_received = pyqtSignal(str)
    
    def __init__(self):
        # Initialize QWidget
        super().__init__()
        
        # Default hostname and port number
        self.HOST = "localhost"
        self.PORT = 12345

        self.setWindowTitle("Client user")
        self.setFixedSize(900, 600)

        # Create the main layout for the Client window
        self.mainLayout = QVBoxLayout(self)

        # Create the stacked widget
        self.stackedWidget = QStackedWidget()

        # Setup main menu and chat window
        self._setupMainMenu()
        self._initializeChatWindow()

        # Add stackedWidget to the main layout
        self.mainLayout.addWidget(self.stackedWidget)

        # Set the default index to the main menu
        self.stackedWidget.setCurrentIndex(0)

        # Set the layout of the server to the main layout
        self.setLayout(self.mainLayout)
        
        # Generate public and private keys
        self.key_length = 1024
        self.public_key, self.private_key = rsa.newkeys(self.key_length)
        
        self.server_public_key = None
        
        self.name = "Client"
        
        self.host_exit = True
        
        self.conn = None

        # Connect the signal to the slot
        self.message_received.connect(self.displayMessage)

    def _setupMainMenu(self):
        # Main menu will have a welcome message and a start button
        mainMenu = QWidget(self)
        mainMenuLayout = QVBoxLayout(mainMenu)

        self.mainMenuMessage = QTextEdit(self)
        self.mainMenuMessage.setReadOnly(True)
        self.mainMenuMessage.append("Welcome to chat client!")

        # Hostname and port number can be entered here by the user
        self.hostLabel = QTextEdit(self)
        self.hostLabel.setPlaceholderText("Enter the hostname (default: localhost)")

        self.portLabel = QTextEdit(self)
        self.portLabel.setPlaceholderText("Enter the port number (default: 12345)")

        inputLabel = QHBoxLayout()
        inputLabel.addWidget(self.hostLabel)
        inputLabel.addWidget(self.portLabel)

        inputWidget = QWidget()
        inputWidget.setLayout(inputLabel)
        
        # Add name input
        self.nameLabel = QTextEdit(self)
        self.nameLabel.setPlaceholderText("Enter your name (default: Guest)")
        
        # Add start button
        startButton = QPushButton("Start", self)
        startButton.clicked.connect(self.startChat)

        mainMenuLayout.addWidget(self.mainMenuMessage)
        mainMenuLayout.addWidget(inputWidget)
        mainMenuLayout.addWidget(self.nameLabel)
        mainMenuLayout.addWidget(startButton)

        mainMenu.setLayout(mainMenuLayout)

        self.stackedWidget.addWidget(mainMenu)

    def _initializeChatWindow(self):
        # Initialize the chat window
        chatWindow = QWidget()
        chatLayout = QVBoxLayout()

        # Message display area
        self.messageDisplay = QTextEdit(self)
        self.messageDisplay.setReadOnly(True)

        # Message input box
        self.messageSend = QTextEdit(self)
        self.messageSend.setPlaceholderText("Type your message here...")

        # Send button
        self.sendButton = QPushButton("Send", self)
        self.sendButton.clicked.connect(self.sendMessage)

        # Add widgets
        chatLayout.addWidget(self.messageDisplay)
        chatLayout.addWidget(self.messageSend)
        chatLayout.addWidget(self.sendButton)

        chatWindow.setLayout(chatLayout)

        # Add to stacked widget
        self.stackedWidget.addWidget(chatWindow)

    def startChat(self):
        # Switch to the chat window
        self.stackedWidget.setCurrentIndex(1)
        QApplication.processEvents()
        self.setupClient()

    def setupClient(self):
        # Create the socket
        self.conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.conn.settimeout(5)

        # Get the hostname and port number from the user (self-hostLabel and self-portLabel)
        if self.hostLabel.toPlainText().strip():
            self.HOST = self.hostLabel.toPlainText().strip()

        if self.portLabel.toPlainText().strip():
            self.PORT = int(self.portLabel.toPlainText().strip())
            
        # Get the name from the user
        name_label = self.nameLabel.toPlainText().strip()
        
        # Remove anything with <> in the name
        name_label = re.sub("<.*>", "", name_label)
        self.name = name_label if name_label else "Guest"

        # Connect to the server
        try:
            self.conn.connect((self.HOST, self.PORT))
            print("Connected to", self.HOST)
            
            self.conn.settimeout(None)
            
            self.host_exit = False
            
            print("Sending public key and name")
            # Send public key and name to server
            message = f"<NAME>{self.name}<NAME>{self.public_key.save_pkcs1().decode()}"
            self.conn.sendall(message.encode())
            
            print("Sent key and name")
            
            # Receive server's public key
            print("Receiving server's public key")
            public_key = self.conn.recv(1024).decode()
            self.server_public_key = rsa.PublicKey.load_pkcs1(public_key)
            print("Public key received!", self.server_public_key.n)
        except (ConnectionRefusedError, socket.timeout):
            print("Connection refused. Make sure the server is running.")
            # Go back to the main menu
            self.stackedWidget.setCurrentIndex(0)
            self.mainMenuMessage.setText("Connection refused. Make sure the server is running.")
            return
        print("Connected to server")

        # Start receiving messages in a separate thread
        threading.Thread(target=self.receiveMessage, daemon=True).start()
        
    def chunkMessage(self, message):
            # Chunk size is key/8 - 11, the maximum size of RSA encryption
            # An extra byte is added for padding
            chunk_size = self.key_length // 8 - 11 - 1
            
            # Remove disallowed codes
            message = re.sub("<END>", "", message)
            message = re.sub("<SERVER_BROADCAST>", "", message)
            
            # Return a list of the message in chunks
            # Iterating with a step of chunk_size
            chunks = [message[i:i+chunk_size] for i in range(0, len(message), chunk_size)]
            
            # Add end of message code
            chunks[-1] += "<END>"       # Additional end code is added to the last chunk for reconstruction
            
            return chunks

    def sendMessage(self, message=None):
        # Send message after user input
        message = self.messageSend.toPlainText().strip()
        # Disallow repeated newlines
        message = re.sub("\n+", "\n", message)
        # Disallow any <> codes
        message = re.sub("<.*>", "", message)
        
        if message:
            self.messageDisplay.append(f"You: {message}")
            message = f"{self.name}: {message}"
            # Encrypt with server's public key
            chunked_message = self.chunkMessage(message)
            for chunk in chunked_message:
                encrypted_chunk = rsa.encrypt(chunk.encode(), self.server_public_key)
                print("Encrypting message with server's public key:", encrypted_chunk)
                self.conn.sendall(encrypted_chunk)
                print("Message sent!")
            self.messageSend.clear()

        if message.lower() == "exit":
            self.exit()

    def receiveMessage(self):
        reconstructed_message = ""
        while True:
            try:
                data = self.conn.recv(1024)
                print("Received:", data)
                if data == b"<HOST_EXIT>":
                    print("Server has closed the connection.")
                    self.host_exit = True
                    self.exit()
                    break
                
                # Decrypt using client's private key
                decrypted_chunk = rsa.decrypt(data, self.private_key).decode()
                print("Decrypted message:", decrypted_chunk)
                
                reconstructed_message += decrypted_chunk
                if reconstructed_message and "<END>" in reconstructed_message:
                    reconstructed_message = re.sub("<END>", "", reconstructed_message)
                    # Check for Server broadcast message (includes a code, can be a broadcast or another Client's message)
                    if "<SERVER_BROADCAST>" in reconstructed_message:
                        # Display without the broadcast message prefix
                        reconstructed_message = re.sub("<SERVER_BROADCAST>", "", reconstructed_message)
                        
                        # Check for host exit message
                        if reconstructed_message == "<HOST_EXIT>":
                            print("Server has closed the connection.")
                            self.host_exit = True
                            self.exit()
                        else:
                            self.message_received.emit(reconstructed_message)
                            reconstructed_message = ""
                    else:
                        self.message_received.emit(reconstructed_message)
                        reconstructed_message = ""
                    QApplication.processEvents()
            except:
                break

    def displayMessage(self, message):
        self.messageDisplay.append(message)
        self.messageSend.clear()
        self.messageSend.setPlaceholderText("Type your message here...")

    def exit(self):
        # Send exit message and close the connection
        if not self.host_exit:
            print("Sending 'exit'")
            self.conn.sendall("exit".encode())
        if self.conn:
            self.conn.close()
        print("Thanks for chatting!")
        self.close()
        
    # Override the closeEvent method to handle the close event
    def closeEvent(self, event):
        print("Closing server by app close...")
        self.exit()
        
        event.accept()

def main():
    app = QApplication([])
    window = Client()
    window.show()
    app.exec_()


if __name__ == "__main__":
    main()
