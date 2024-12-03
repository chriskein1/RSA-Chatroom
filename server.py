# Networking Final Project
# Chris Keiningham

# Server program: Act as a user as well as the host of an IM chat room. The server can send and receive messages,
# handle multiple client connections concurrently, and broadcast messages to all clients.

# Uses both a GUI and threads for multiple connections, as well as a worker thread to handle constant message receiving.

import socket
import threading
from PyQt5.QtWidgets import QApplication, QWidget, QTextEdit, QVBoxLayout, QHBoxLayout, QPushButton, QStackedWidget
import rsa      # For encrypting and decrypting messages, use pip install rsa
import re

# Create object for client connection
class Connection:
    def __init__(self, conn, addr, name, public_key):
        self.conn = conn
        self.addr = addr
        self.name = name
        self.public_key = public_key

class Server(QWidget):
    def __init__(self, maxConnections=5):
        # Initialize QWidget
        super().__init__()
        
        self.setWindowTitle("Server user")
        self.setFixedSize(900, 600)
        
        # Create a main layout for the Server window
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
        
        # Set max connections
        self.maxConnections = maxConnections
        
        # Client dictionary
        self.clients = {}
        
        # Client ID, for assigning unique IDs to clients
        self.clientID = 0
        
        # Lock for handling multiple connections
        self.lock = threading.Lock()
        
        # Generate RSA keys
        self.key_length = 1024
        self.public_key, self.private_key = rsa.newkeys(self.key_length)
        
        self.name = "Host"
        
        self.code = "<SERVER_BROADCAST>"
        
        self.shutdown = False
                
    def _setupMainMenu(self):
        # Main menu will have a welcome message and a start button
        mainMenu = QWidget(self)
        mainMenuLayout = QVBoxLayout(mainMenu)
        
        self.mainMenuMessage = QTextEdit(self)
        self.mainMenuMessage.setReadOnly(True)
        self.mainMenuMessage.append("Welcome to chat server!")
        
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
        self.nameLabel.setPlaceholderText("Enter your name (default: Host)")
        
        # Add start button
        startButton = QPushButton("Start", self)
        startButton.clicked.connect(self.startChat)
        
        # Add everything to the main menu layout
        mainMenuLayout.addWidget(self.mainMenuMessage)
        mainMenuLayout.addWidget(inputWidget)
        mainMenuLayout.addWidget(self.nameLabel)
        mainMenuLayout.addWidget(startButton)

        mainMenu.setLayout(mainMenuLayout)
        
        self.stackedWidget.addWidget(mainMenu)
        
    def _initializeChatWindow(self):
        chatWindow = QWidget()
        chatLayout = QVBoxLayout()
        
        # Message display area
        self.messageDisplay = QTextEdit(self)
        self.messageDisplay.setReadOnly(True)  # Display is read-only
        
        # Message input box
        self.messageSend = QTextEdit(self)
        self.messageSend.setPlaceholderText("Type your message here...")
        
        # Send button
        sendButton = QPushButton("Send", self)
        sendButton.clicked.connect(self.sendMessage)
        
        # Add widgets
        chatLayout.addWidget(self.messageDisplay)
        chatLayout.addWidget(self.messageSend)
        chatLayout.addWidget(sendButton)
        
        # Set vertical box layout
        chatWindow.setLayout(chatLayout)
        
        # Add to stacked widget
        self.stackedWidget.addWidget(chatWindow)

    def startChat(self):
        self.stackedWidget.setCurrentIndex(1)
        QApplication.processEvents()
        try:
            self.setupServer()
        except OSError:
            # If the port is already in use, display an error message
            self.mainMenuMessage.append("Port is already in use. Please try again.")
            self.stackedWidget.setCurrentIndex(0)

    def setupServer(self):
        # Create the socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Use local variables for host and port
        HOST = "localhost" if not self.hostLabel.toPlainText().strip() else self.hostLabel.toPlainText().strip()
        PORT = 12345 if not self.portLabel.toPlainText().strip() else int(self.portLabel.toPlainText().strip())
        
        # Get the name from the user
        name_label = self.nameLabel.toPlainText().strip()
        # Remove anything with <> in the name
        name_label = re.sub("<.*>", "", name_label)
        self.name = name_label if name_label else "Host"
        
        # Bind the socket to the address
        self.socket.bind((HOST, PORT))
        
        print("Server initialized.")
        print("Public key: ", self.public_key)
        print("Private key: ", self.private_key)
        
        # Listen for incoming connections
        self.socket.listen()
        
        accept_thread = threading.Thread(target=self.acceptConnections, daemon=True)
        accept_thread.start()
        
    def acceptConnections(self):
        # Accept connections until the maximum number of connections is reached
        while not self.shutdown and len(self.clients) < self.maxConnections:
            try:
                # Accept the connection
                conn, addr = self.socket.accept()
                print("Connected by", addr)
                
                with self.lock:
                    # Create connection object
                    self.clientID += 1                
                    print(f"Receiving information from Client ID: {self.clientID}...")
                    # Get name and public key and from client
                    message = conn.recv(1024).decode()
                    # Name will be in <NAME>name<NAME> format
                    name = re.search("<NAME>(.*)<NAME>", message).group(1)
                    # Remove the name from the message
                    message = re.sub("<NAME>.*<NAME>", "", message)

                    # Public key will be the rest of the message
                    public_key = message
                    print(f"Name: {name}, Public key: {public_key} #")
                    
                    # Public key is sent as pkcs1
                    public_key = rsa.PublicKey.load_pkcs1(public_key)
                    print("Final public key:", public_key)
                    client = Connection(conn, addr, name, public_key)
                    
                    clientIndex = self.clientID
                    
                    # Add the client to the dictionary
                    self.clients[clientIndex] = client
                    
                    # Send client server's public key
                    conn.sendall(self.public_key.save_pkcs1())                
                
                # Start a thread to handle receiving messages
                receive_thread = threading.Thread(target=self.receiveMessage, args=(clientIndex,), daemon=True)
                receive_thread.start()
                
                # Add message that a new user has joined
                message = f"|--------User {name} has joined the chat--------|"
                self.messageDisplay.append(message)
                
                # Broadcast the message to all other clients
                self.broadcastMessage(message, clientIndex)
            except:
                break
            
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
                        
    def broadcastMessage(self, message, clientIndex=None):
        
        # Remove repeated newlines
        message = re.sub("\n+", "\n", message)
        
        # Remove end or broadcast codes
        message = re.sub("<END>", "", message)
        message = re.sub("<SERVER_BROADCAST>", "", message)
        
        # Add the code to the message, name if host is sending the message
        message = self.code + message
        
        print("Sending message", message)
        
        # Get the chunked message
        chunked_message = self.chunkMessage(message)
        
        with self.lock:
            # Iterate through dictionary and send message to all clients
            for clientID in self.clients:
                # Do not send the message to the client that sent it as they display it themselves
                if clientIndex is not None and clientID != clientIndex:
                    # Encrypt the message using the client's public key
                    client = self.clients[clientID]
                    try:
                        for chunk in chunked_message:
                            print("Encrypting message with client's public key:", client.public_key)
                            encrypted_chunk = rsa.encrypt(chunk.encode(), client.public_key)
                            client.conn.sendall(encrypted_chunk)
                    except:
                        print("Error sending message to client", clientID)
                        self.closeConnection(clientID)
                            
    def sendMessage(self):
        message = self.messageSend.toPlainText().strip()
        # Disallow repeated newlines
        message = re.sub("\n+", "\n", message)
        # Disallow <> codes
        message = re.sub("<.*>", "", message)
        
        if message and message.lower() != "exit":
            self.messageDisplay.append(f"You: {message}")
            message = f"{self.name}: {message}"
            
            chunked_message = self.chunkMessage(message)
            
            print("Chunked message:", chunked_message)
            
            with self.lock:
                for clientID in self.clients:
                    # Encrypt the message using the client's public key
                    print("Encrypting message with client's public key:", self.clients[clientID].public_key)
                    client = self.clients[clientID].conn
                    
                    for chunk in chunked_message:
                        encrypted_chunk = rsa.encrypt(chunk.encode(), self.clients[clientID].public_key)
                        client.sendall(encrypted_chunk)
                        print("Sending message", encrypted_chunk)

            self.messageSend.clear()
        
        else:
            print("EXITING")
            self.exit()

    def receiveMessage(self, clientIndex):
        try:
            conn = self.clients[clientIndex].conn
            reconstructed_message = ""
            while True:
                # Message is received, encrypted with server's public key
                try:
                    encrypted_chunk = conn.recv(1024)
                    print("Message received", encrypted_chunk)
                    
                    if encrypted_chunk == b'exit':
                        self.closeConnection(clientIndex)
                        continue
                    # Decrypt the message using server's private key
                    print("Decrypting message")
                    # Decrypt using server's private key
                    decrypted_chunk = rsa.decrypt(encrypted_chunk, self.private_key)
                    decrypted_chunk = decrypted_chunk.decode()
                    
                    print("Chunk decrypted:", decrypted_chunk)
                    
                    reconstructed_message += decrypted_chunk
                    
                    # Check for end of message code
                    if "<END>" in reconstructed_message:
                        # Remove the end code
                        reconstructed_message = re.sub("<END>", "", reconstructed_message)
                        
                        print("Reconstructed message:", reconstructed_message)
                        # Display the message
                        self.messageDisplay.append(reconstructed_message)
                        QApplication.processEvents()  # Update GUI
                        
                        # Broadcast message to all other users
                        self.broadcastMessage(reconstructed_message, clientIndex)
                        
                        reconstructed_message = ""                   
                    
                except rsa.DecryptionError:
                    print("Error decrypting. Wrong key?")
                    break
            
                # Catch error from when user force quits.
                except:
                    print("User has left the chat.")
                    break
        except:
            # Close the connection
            self.closeConnection(clientIndex)
            
    def closeConnection(self, clientIndex):
        # Remove the client from the list
        with self.lock:
            conn = self.clients[clientIndex].conn
            name = self.clients[clientIndex].name
            conn.close()
            del self.clients[clientIndex]
        
        # Broadcast the message that the user has left
        message = f"|--------User {name} has left the chat--------|"
        self.messageDisplay.append(message)
        self.broadcastMessage(message, clientIndex)
        
    def exit(self):
        # Send exit message
        self.shutdown = True

        with self.lock:
            for clientID in self.clients:
                self.clients[clientID].conn.sendall("<HOST_EXIT>".encode())
                self.clients[clientID].conn.close()
            self.socket.close()
            print("Thanks for chatting!")
            self.close()
            # Close the application
            QApplication.quit()
            
    # Override the closeEvent method to handle the close event
    def closeEvent(self, event):
        print("Closing server by app close...")
        self.exit()
        
        event.accept()

def main():
    # Create a Qt application
    app = QApplication([])

    # Create a Qt widget (window)
    server = Server()
    
    # Show the window
    server.show()
    
    app.exec_()
    

if __name__ == "__main__":
    main()
