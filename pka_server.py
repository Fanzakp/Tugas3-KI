import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import pickle
import time
import sys
import json
import os

class EnhancedPublicKeyAuthority:
    def __init__(self, host='localhost', port=5001, key_dir='client_keys'):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, port))
        self.server.listen(5)
        self.server.settimeout(10)
        
        # Create directory for storing client public keys
        self.key_dir = key_dir
        os.makedirs(self.key_dir, exist_ok=True)
        
        # Generate PKA's key pair
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        self.clients = {}  # client_id -> {public_key, timestamp, socket}
        self.lock = threading.Lock()
        self.running = True
        
        print("Enhanced Public Key Authority initialized")

    def save_client_public_key(self, client_id, public_key_bytes):
        """Save client public key to file"""
        key_path = os.path.join(self.key_dir, f"{client_id}_public_key.pem")
        with open(key_path, 'wb') as f:
            f.write(public_key_bytes)

    def load_client_public_key(self, client_id):
        """Load client public key from file"""
        key_path = os.path.join(self.key_dir, f"{client_id}_public_key.pem")
        try:
            with open(key_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            return None

    def validate_key_registration(self, public_key):
        """Additional key validation logic"""
        try:
            # Example validation: Check key size
            key_size = public_key.key_size
            return key_size >= 2048
        except Exception as e:
            print(f"Key validation error: {e}")
            return False

    def handle_client(self, client_socket, address):
        client_id = None
        try:
            print(f"New client connection from {address}")
            client_socket.settimeout(5)

            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break

                    request = pickle.loads(data)
                    request_type = request.get('type', '')

                    if request_type == 'REGISTER':
                        client_id = request['client_id']
                        public_key = request['public_key']

                        # Validate key before registration
                        if not self.validate_key_registration(public_key):
                            response = {
                                'status': 'error',
                                'message': 'Invalid public key'
                            }
                            client_socket.send(pickle.dumps(response))
                            break

                        # Convert public key to bytes for storage
                        public_key_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        )

                        with self.lock:
                            # Save public key to file
                            self.save_client_public_key(client_id, public_key_bytes)
                            
                            self.clients[client_id] = {
                                'public_key': public_key_bytes,
                                'timestamp': time.time(),
                                'socket': client_socket
                            }

                        response = {
                            'status': 'success',
                            'message': 'Registration successful',
                            'pka_public_key': self.get_public_key_bytes()
                        }
                        client_socket.send(pickle.dumps(response))
                        print(f"Client {client_id} registered successfully")

                    elif request_type == 'REQUEST_KEY':
                        requesting_id = request['requesting_client_id']
                        target_id = request['target_client_id']
                        print(f"Key request from {requesting_id} for {target_id}")

                        with self.lock:
                            # First try to load from file
                            target_key_bytes = self.load_client_public_key(target_id)
                            
                            if target_key_bytes:
                                # Create digital signature
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
                    print(f"Client handling error: {e}")
                    break

        finally:
            if client_id and client_id in self.clients:
                with self.lock:
                    del self.clients[client_id]
            try:
                client_socket.close()
            except:
                pass

    def get_public_key_bytes(self):
        """Get PKA's public key in bytes"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def create_signature(self, public_key_bytes):
        """Create digital signature for public key"""
        try:
            signature = self.private_key.sign(
                public_key_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            print(f"Signature creation error: {e}")
            return None

    def start(self):
        print(f"Enhanced PKA Server started on localhost:5001")
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

        except KeyboardInterrupt:
            print("\nServer shutdown initiated")
        finally:
            self.cleanup()

    def cleanup(self):
        """Comprehensive server cleanup"""
        print("Initiating server cleanup...")
        self.running = False

        with self.lock:
            for client_id, client_info in list(self.clients.items()):
                try:
                    client_info['socket'].close()
                except:
                    pass

        self.clients.clear()
        try:
            self.server.close()
        except:
            pass

        print("Server shutdown complete")

def main():
    pka_server = EnhancedPublicKeyAuthority()
    try:
        pka_server.start()
    except Exception as e:
        print(f"Fatal error: {e}")
        pka_server.cleanup()
    finally:
        sys.exit(0)

if __name__ == "__main__":
    main()