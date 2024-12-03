# CSCI 4300: Data Communication Networks Final Project
### Chris Keiningham

This program acts as a client-server instant messaging program, using the RSA encryption scheme

---------------------------------------------
Sections


(i) How to install

(ii) How to run

(iii) How it works

---------------------------------------------
(i) How to install

Prerequisites:

Python 3.9+

PyQt5

RSA

---------------------------------------------
Use the following commands if necessary:

`pip install pyqt5`

`pip install rsa`


---------------------------------------------
(ii) How to run

To run, simply navigate to the directory and start the desired Python program.

To host, start server.py with the command:

`python3 server.py`


If running locally, use localhost as the IP address (default), or enter your machine's IP address.

Use local IP if running on LAN, or machine's public IP and port using port forwarding to message across networks.

Enter a name and hit start when ready to chat.


To connect to the host, start client.py with the command:

`python3 client.py`


Then, enter the IP and port information of the host.

Enter a name and hit start when ready to chat.


The chat messages can be sent back and forth as desired, with multiple users connecting to the host.

A client can join and exit as desired.

Once the host exits, all client connections will disconnect and exit the program.


Debugging information is available in the console.


---------------------------------------------
(iii) How it works

This program uses sockets to handle the connections and threading to:

1) Handle multiple client connections for the server
2) Handle calling the recv() function from the worker thread while displaying the GUI.


Messages are encrypted using the RSA cryptosystem.

When a server is created by the host, an RSA public/private key pair are generated and stored in memory.

When a client connects, it also creates an RSA public/private key pair.


The client and host exchange public keys, and the client sends the host its name.

The server file stores this information in a class for the client connection.


A client can only communicate with the server, so the server will broadcast received messages to every client

except the one who sent the message. 

Further, the server will broadcast information such as clients leaving/joining the room.

A broadcast includes the code at the beginning: "<SERVER_BROADCAST>". 

Only the server is permitted to send messages such as this. 

All messages the host or client tries to send will have anything withing <*> be removed by Regular Expressions.


Every message the server sends will be encrypted with each client's public key. 

The client will then decrypt with its own private key.

Likewise, the client will send a message to the server using the server's public key.

The server then decrypts the message with its own private key. 

Then, the server will broadcast the received message to all other clients, encrypting with each client's public key.


To handle sending messages, RSA only allows up to the size key_length/8 - 11. 

For 1024 bit encryption, that is only 117 bytes of data that can be sent. 


To allow longer messages, chunking was used along with an <END> code to designate when the last chunk has been received.

Each receiver will reconstruct and decrypt a received chunk using its own private key.


When the server is closed, a message is sent to the server, and the connection is closed.

If other users are still connected, the server will broadcast a message stating the client has left.

If the server disconnects, each client is removed from the chat room.


The GUI is created with PyQt5, and each entry box is a QTextEdit object that is converted to plain text each time

either the Send or Start button is selected.
There is both a main menu and chat scene, which is switched by using a stacked widget.
