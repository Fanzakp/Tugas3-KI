import socket
import threading
from des_implementation import generate_random_key

def handle_client(client_socket, client_address, clients, encryption_key):
    """Handle individual client connection and message forwarding"""
    print(f"New connection from {client_address}")
    
    try:
        while True:
            message = client_socket.recv(4096).decode()
            if not message:
                break
            
            # Forward message to all other clients
            for client in clients:
                if client != client_socket:
                    try:
                        client.send(message.encode())
                    except:
                        clients.remove(client)
                        
    except:
        print(f"Client {client_address} disconnected")
    finally:
        clients.remove(client_socket)
        client_socket.close()

def server_program():
    host = socket.gethostname()
    port = 5000
    
    server_socket = socket.socket()
    server_socket.bind((host, port))
    server_socket.listen(2)
    
    clients = []
    # Generate one encryption key for all clients
    encryption_key = generate_random_key()
    print(f"Generated encryption key: {encryption_key}")
    
    try:
        while len(clients) < 2:  # Accept only 2 clients
            client_socket, address = server_socket.accept()
            clients.append(client_socket)
            
            # Send encryption key to client
            client_socket.send(f"KEY:{encryption_key}".encode())
            
            # Start a new thread to handle client
            thread = threading.Thread(target=handle_client, args=(client_socket, address, clients, encryption_key))
            thread.daemon = True
            thread.start()
            
            # Notify clients about connection status
            if len(clients) == 1:
                client_socket.send("SYS:Waiting for another user to connect...".encode())
            elif len(clients) == 2:
                for client in clients:
                    client.send("SYS:Chat session started! You can now exchange messages.".encode())
        
        # Keep server running
        while True:
            if len(clients) < 2:
                break
    
    except KeyboardInterrupt:
        print("\nServer shutting down...")
    finally:
        for client in clients:
            client.close()
        server_socket.close()

if __name__ == '__main__':
    server_program()