import socket
import threading

# Server constants
HOST = '0.0.0.0'
PORT = 5556

clients = {}  # Store connected clients with their usernames

def broadcast(message, sender_client=None):
    """Send a message to all clients except the sender."""
    for client in clients:
        if client != sender_client:
            try:
                client.send(message)
            except:
                remove_client(client)

def handle_client(client):
    """Handle incoming messages from a client."""
    try:
        username = client.recv(1024).decode('utf-8')  # Receive the username
        if not username:
            raise ValueError("Username missing")
        
        clients[client] = username
        print(f"{username} joined the chat")
        
        while True:
            encrypted_message = client.recv(1024)  # Receive the encrypted message
            if not encrypted_message:
                break
            broadcast(f"{username}: ".encode() + encrypted_message, sender_client=client)
    
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        remove_client(client)

def remove_client(client):
    """Remove a client from the clients list and close the connection."""
    username = clients.pop(client, "Unknown")
    print(f"{username} left the chat")
    client.close()

def server():
    """Run the chat server."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Server started on {HOST}:{PORT}")
    
    while True:
        client, addr = server_socket.accept()
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    server()
