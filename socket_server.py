import socket
import threading
import json
from rsa_implementation import RSA
from des_implementation import des_encrypt, des_decrypt, generate_random_key  # Added import

class PKAServer:
    def __init__(self):
        self.host = socket.gethostname()
        self.port = 5000
        self.server_socket = socket.socket()
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}
        self.rsa = RSA(key_size=2048)
        self.rsa.generate_keys()
        print("PKA Server RSA keys generated")

        print("\n[PKA SERVER KEY GENERATION]")
        print("Generated RSA key pair for PKA Server:")
        print(f"Public Key (e): {self.rsa.public_key[0]}")
        print(f"Public Key (n): {self.rsa.public_key[1]}")
        print(f"Private Key (d): {self.rsa.private_key[0]}")
        print(f"Private Key (n): {self.rsa.private_key[1]}")
        print("\nPKA Server is ready to sign client public keys")
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"PKA Server started on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"New connection from {address}")
                thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            self.cleanup()
    
    def sign_public_key(self, client_id, public_key):
        """Sign client's public key"""
        print(f"\n[PKA SERVER SIGNING PROCESS for {client_id}]")
        print("1. Creating signature data structure")
        key_data = {
            'client_id': client_id,
            'public_key': public_key
        }
        key_str = json.dumps(key_data)
        print("2. Signing public key with PKA private key...")
        signature = self.rsa.sign(key_str)
        print("3. Signature generated successfully")
        return signature
    
    def encrypt_client_data(self, data, client_pub_key):
        """Encrypt data using hybrid encryption (DES + RSA)"""
        try:
            # Generate a random DES key
            des_key = generate_random_key()
            
            # Encrypt the actual data with DES
            data_str = json.dumps(data)
            encrypted_data = des_encrypt(data_str, des_key)
            
            # Encrypt the DES key with RSA
            encrypted_key = self.rsa.encrypt_key(des_key, client_pub_key)
            
            # Combine both pieces
            result = {
                'key': encrypted_key,
                'data': encrypted_data
            }
            
            return json.dumps(result)
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise
    
    def broadcast_new_client(self, new_client_id, public_key, signature, peer_port):
        """Broadcast new client's signed public key using hybrid encryption"""
        for client_id, info in self.clients.items():
            if client_id != new_client_id:
                try:
                    client_pub_key = (int(info['public_key']['e']), int(info['public_key']['n']))
                    
                    # Generate DES key for hybrid encryption
                    des_key = generate_random_key()
                    
                    # Prepare the data
                    key_data = {
                        'client_id': new_client_id,
                        'public_key': public_key,
                        'signature': signature,
                        'peer_port': peer_port
                    }
                    
                    # Encrypt data with DES
                    data_str = json.dumps(key_data)
                    encrypted_data = des_encrypt(data_str, des_key)
                    
                    # Encrypt DES key with RSA
                    encrypted_key = self.rsa.encrypt_key(des_key, client_pub_key)
                    
                    # Combine both pieces
                    encrypted_package = {
                        'key': encrypted_key,
                        'data': encrypted_data
                    }
                    
                    # Send the package
                    message = f"NEW:{json.dumps(encrypted_package)}"
                    info['socket'].send(message.encode())
                    print(f"Successfully broadcast new client {new_client_id} to {client_id}")
                    
                except Exception as e:
                    print(f"Error sending to {client_id}: {str(e)}")
    
    def handle_client(self, client_socket, address):
        try:
            # Send PKA's public key
            pka_pub_key = {
                'e': str(self.rsa.public_key[0]),
                'n': str(self.rsa.public_key[1])
            }
            client_socket.send(f"PKA:{json.dumps(pka_pub_key)}".encode())
            
            # Receive client's registration
            data = client_socket.recv(4096).decode()
            if not data.startswith("REG:"):
                raise Exception("Invalid registration format")
                
            # Parse registration data
            reg_data = json.loads(data[4:])
            client_id = reg_data['client_id']
            public_key = reg_data['public_key']
            peer_port = reg_data.get('peer_port')
            
            print(f"Registering client {client_id} with peer port {peer_port}")
            
            # Sign client's public key
            signature = self.sign_public_key(client_id, public_key)
            
            # Store client information
            self.clients[client_id] = {
                'socket': client_socket,
                'address': address,
                'public_key': public_key,
                'signature': signature,
                'peer_port': peer_port
            }
            
            # Prepare and encrypt other clients' data
            other_clients = {}
            client_pub_key = (int(public_key['e']), int(public_key['n']))
            
            for cid, info in self.clients.items():
                if cid != client_id:
                    client_data = {
                        'client_id': cid,
                        'public_key': info['public_key'],
                        'signature': info['signature'],
                        'peer_port': info['peer_port']
                    }
                    encrypted_package = self.encrypt_client_data(client_data, client_pub_key)
                    other_clients[cid] = json.loads(encrypted_package)
            
            # Send registration acknowledgment
            response = {
                'status': 'registered',
                'signature': signature,
                'other_clients': other_clients
            }
            client_socket.send(f"ACK:{json.dumps(response)}".encode())
            
            # Broadcast new client to others
            self.broadcast_new_client(client_id, public_key, signature, peer_port)
            
            # Handle ongoing communication
            while True:
                data = client_socket.recv(4096).decode()
                if not data:
                    break
                    
                if data.startswith("GET:"):
                    requested_id = data[4:]
                    if requested_id in self.clients:
                        info = self.clients[requested_id]
                        key_data = {
                            'client_id': requested_id,
                            'public_key': info['public_key'],
                            'signature': info['signature'],
                            'peer_port': info['peer_port']
                        }
                        encrypted_package = self.encrypt_client_data(
                            key_data,
                            (int(public_key['e']), int(public_key['n']))
                        )
                        client_socket.send(f"KEY:{encrypted_package}".encode())
                    else:
                        client_socket.send("ERR:Client not found".encode())
                        
        except Exception as e:
            print(f"Error handling client {address}: {str(e)}")
        finally:
            self.handle_client_disconnect(client_socket)
    
    def handle_client_disconnect(self, client_socket):
        for client_id, info in list(self.clients.items()):
            if info['socket'] == client_socket:
                print(f"Client {client_id} disconnecting")
                del self.clients[client_id]
                disconnect_msg = {'client_id': client_id}
                for other_info in self.clients.values():
                    try:
                        other_info['socket'].send(f"DISC:{json.dumps(disconnect_msg)}".encode())
                    except:
                        pass
                break
        try:
            client_socket.close()
        except:
            pass
    
    def cleanup(self):
        for info in self.clients.values():
            try:
                info['socket'].close()
            except:
                pass
        try:
            self.server_socket.close()
        except:
            pass

def main():
    server = PKAServer()
    server.start()

if __name__ == "__main__":
    main()