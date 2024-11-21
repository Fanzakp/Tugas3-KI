import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import pickle
import time
import sys

class PublicKeyAuthority:
    def __init__(self, host='localhost', port=5001):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(5)
        self.server.settimeout(10)  # Timeout untuk menerima koneksi
        print("Initializing Public Key Authority...")
        
        # Generate PKA's key pair
        print("Generating PKA key pair...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        print("PKA key pair generated successfully")
        
        self.clients = {}  # client_id -> {public_key, socket}
        self.lock = threading.Lock()
        self.running = True

    def get_public_key_bytes(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def create_signature(self, public_key_bytes):
        """Create digital signature for public key."""
        try:
            signature = self.private_key.sign(
                public_key_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Digital signature created successfully")
            return signature
        except Exception as e:
            print(f"Error creating signature: {e}")
            return None

    def handle_client(self, client_socket, address):
        client_id = None
        try:
            print(f"\nNew client connected from {address}")
            client_socket.settimeout(5)  # Timeout untuk menerima data

            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    request = pickle.loads(data)
                    if not isinstance(request, dict) or 'type' not in request:
                        print(f"Invalid request format from {address}")
                        break

                    request_type = request.get('type', '')

                    if request_type == 'REGISTER':
                        client_id = request['client_id']
                        public_key = request['public_key']
                        print(f"\nRegistering client {client_id}")

                        with self.lock:
                            self.clients[client_id] = {
                                'public_key': public_key,
                                'socket': client_socket
                            }

                        response = {
                            'status': 'success',
                            'message': 'Registration successful'
                        }
                        client_socket.send(pickle.dumps(response))
                        print(f"Client {client_id} registered successfully")

                    elif request_type == 'REQUEST_KEY':
                        requesting_id = request['requesting_client_id']
                        target_id = request['target_client_id']
                        print(f"\nClient {requesting_id} requesting public key of {target_id}")

                        with self.lock:
                            if target_id in self.clients:
                                target_key = self.clients[target_id]['public_key']
                                target_key_bytes = target_key.public_bytes(
                                    encoding=serialization.Encoding.PEM,
                                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                                )
                                signature = self.create_signature(target_key_bytes)

                                response = {
                                    'status': 'success',
                                    'public_key': target_key_bytes,
                                    'signature': signature,
                                    'timestamp': time.time()
                                }
                            else:
                                response = {
                                    'status': 'error',
                                    'message': 'Target client not found'
                                }

                        client_socket.send(pickle.dumps(response))

                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error handling client: {e}")
                    break

        finally:
            if client_id and client_id in self.clients:
                with self.lock:
                    del self.clients[client_id]
            try:
                client_socket.close()
                print(f"Connection closed for client {client_id}")
            except:
                pass

    def notify_shutdown(self):
        """Notify all clients of server shutdown."""
        print("\nNotifying clients of shutdown...")
        shutdown_msg = pickle.dumps({
            'type': 'PKA_SHUTDOWN',
            'message': 'PKA server is shutting down'
        })

        with self.lock:
            for client_id, client_info in self.clients.items():
                try:
                    client_info['socket'].send(shutdown_msg)
                except:
                    pass

    def cleanup(self):
        """Clean up server resources."""
        print("\nInitiating PKA server shutdown...")
        self.running = False
        self.notify_shutdown()

        with self.lock:
            for client_id, client_info in self.clients.items():
                try:
                    client_info['socket'].close()
                except:
                    pass

        self.clients.clear()
        try:
            self.server.close()
        except:
            pass

        print("PKA server shutdown complete")

    def start(self):
        print(f"\nPKA Server started on localhost:5001")
        print("Press Ctrl+C to shutdown server")

        try:
            while self.running:
                try:
                    client_socket, address = self.server.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error accepting connection: {e}")

        except KeyboardInterrupt:
            print("\nCtrl+C detected")
        finally:
            self.cleanup()

def main():
    pka_server = PublicKeyAuthority()
    try:
        pka_server.start()
    except Exception as e:
        print(f"\nFatal error: {e}")
        pka_server.cleanup()
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()