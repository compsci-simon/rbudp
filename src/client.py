import socket
import threading

# Define the server address and port
HOST = '127.0.0.1'
PORT = 8080

# Create a socket object and connect to the server
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))

# Function to receive messages from the server
def receive():
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
        except:
            # If there is an error, close the client socket
            client_socket.close()
            break

# Function to send messages to the server
def send():
    while True:
        message = input()
        client_socket.send(message.encode('utf-8'))

msg = client_socket.recv(1024).decode('utf8')
print(msg)
name = input()
client_socket.send(name.encode('utf8'))
# Start two threads to handle receiving and sending messages
receive_thread = threading.Thread(target=receive)
receive_thread.start()

send_thread = threading.Thread(target=send)
send_thread.start()
