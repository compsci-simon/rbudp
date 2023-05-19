import socket
import threading

# Define the server address and port
HOST = '127.0.0.1'
PORT = 8080

# Create a socket object and bind it to the server address and port
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()

# List to keep track of all the client connections
clients = []

# Function to handle incoming messages from a client
def handle_client(client_socket):
    client_socket.send(b'What is your name?')
    client_name = client_socket.recv(1024).decode('utf8')
    # Add the client to the list of clients
    clients.append({ 'name': client_name, 'socket': client_socket })
    print(f'Added {client_name} to list of clients')

    # Keep receiving messages from the client and broadcasting them to other clients
    while True:
        try:
            message_parts = client_socket.recv(1024).decode('utf-8').split(' ')
            msg_type = message_parts[0]
            if msg_type == 'b':
              broadcast(' '.join(message_parts[1:]), client_name)
            elif msg_type == 's':
                name = message_parts[1]
                message = ' '.join(message_parts[2:])
                send(message, name, client_name)
        except:
            # If there is an error, remove the client from the list of clients
            clients.remove(client_socket)
            client_socket.close()
            break

# Function to broadcast a message to all clients
def broadcast(message, sender):
    for client in clients:
        client['socket'].send(f'{sender}: {message}'.encode('utf-8'))

def send(message, name, sender):
    for client in clients:
        if client['name'] == name:
            client['socket'].send(f'{sender}: {message}'.encode('utf8'))

print(f'Waiting for incoming connection on the loopback interface at port {PORT}')
# Main loop to accept incoming connections and start a new thread to handle each client
while True:
    client_socket, client_address = server_socket.accept()
    print(f"New connection from {client_address}")
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()
