import socket
import threading
import json
import uuid
from rsa_implementation import RSA
from des_implementation import des_encrypt, des_decrypt, generate_random_key

class P2PClient:
    def __init__(self):
        self.pka_socket = socket.socket()
        self.peer_server = socket.socket()
        self.peer_connections = {}
        self.rsa = RSA(key_size=2048)
        self.client_id = str(uuid.uuid4())[:8]
        self.peer_port = 0
        self.host = socket.gethostname()
        self.pka_public_key = None
        self.signature = None
        
    def verify_client_key(self, client_id, public_key, signature):
        """Verify a client's public key using PKA's signature"""
        print(f"\n[VERIFYING CLIENT {client_id} PUBLIC KEY]")
        print("1. Using PKA public key for verification:")
        print(f"   Public Key (e): {self.pka_public_key[0]}")
        print(f"   Public Key (n): {self.pka_public_key[1]}")
        
        if not self.pka_public_key:
            raise Exception("PKA public key not available")
            
        key_data = {
            'client_id': client_id,
            'public_key': public_key
        }
        key_str = json.dumps(key_data)
        
        print("2. Verifying signature...")
        result = self.rsa.verify_signature(key_str, signature, self.pka_public_key)
        
        if result:
            print("3. Signature verification successful!")
        else:
            print("3. Signature verification failed!")
            
        return result
    
    def start(self, pka_host, pka_port):
        self.rsa.generate_keys()
        print(f"\n[CLIENT {self.client_id} KEY GENERATION]")
        print("Generated RSA key pair for client:")
        print(f"Public Key (e): {self.rsa.public_key[0]}")
        print(f"Private Key (d): {self.rsa.private_key[0]}")
        print(f"n: {self.rsa.public_key[1]}")  # Print n only once
        
        self.start_peer_server()
        
        if self.register_with_pka(pka_host, pka_port):
            self.handle_messages()
        else:
            print("Failed to register with PKA")
            self.cleanup()
    
    def start_peer_server(self):
        try:
            self.peer_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.peer_server.bind((self.host, 0))
            self.peer_port = self.peer_server.getsockname()[1]
            self.peer_server.listen(5)
            
            thread = threading.Thread(target=self.accept_peers)
            thread.daemon = True
            thread.start()
            
            print(f"Peer server started on port {self.peer_port}")
        except Exception as e:
            print(f"Error starting peer server: {str(e)}")
            raise
    
    def register_with_pka(self, host, port):
        try:
            self.pka_socket.connect((host, port))
            
            # Receive PKA's public key
            data = self.pka_socket.recv(4096).decode()
            if not data.startswith("PKA:"):
                raise Exception("Invalid PKA key format")
                
            pka_key_data = json.loads(data[4:])
            self.pka_public_key = (int(pka_key_data['e']), int(pka_key_data['n']))
            print("Received PKA public key")
            
            # Send registration data
            reg_data = {
                'client_id': self.client_id,
                'public_key': {
                    'e': str(self.rsa.public_key[0]),
                    'n': str(self.rsa.public_key[1])
                },
                'peer_port': self.peer_port
            }
            self.pka_socket.send(f"REG:{json.dumps(reg_data)}".encode())
            
            # Receive acknowledgment with signature and other clients
            response = self.pka_socket.recv(4096).decode()
            if response.startswith("ACK:"):
                ack_data = json.loads(response[4:])
                self.signature = ack_data['signature']  # Store PKA's signature of our key
                
                # Process other clients' information
                for client_id, info in ack_data['other_clients'].items():
                    try:
                        # Decrypt and verify client's public key
                        encrypted_data = info['public_key']
                        decrypted_str = self.rsa.decrypt_key(encrypted_data, self.rsa.private_key)
                        key_data = json.loads(decrypted_str)
                        
                        # Verify signature before adding peer
                        if self.verify_client_key(client_id, key_data['key'], key_data['signature']):
                            info['public_key'] = key_data['key']
                            self.add_peer(client_id, info)
                            print(f"Added verified peer: {client_id}")
                        else:
                            print(f"Warning: Invalid signature for peer {client_id}")
                            
                    except Exception as e:
                        print(f"Error processing peer {client_id}: {str(e)}")
                        continue
                
                # Start PKA message handler
                thread = threading.Thread(target=self.handle_pka_messages)
                thread.daemon = True
                thread.start()
                
                return True
                
            return False
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False
    
    def accept_peers(self):
        while True:
            try:
                peer_socket, address = self.peer_server.accept()
                data = peer_socket.recv(4096).decode()
                
                if data.startswith("PEER:"):
                    peer_data = json.loads(data[5:])
                    peer_id = peer_data['client_id']
                    peer_port = peer_data.get('peer_port')
                    
                    if peer_id in self.peer_connections:
                        self.peer_connections[peer_id]['socket'] = peer_socket
                        if peer_port:
                            self.peer_connections[peer_id]['peer_port'] = peer_port
                            
                        thread = threading.Thread(target=self.handle_peer_messages,
                                               args=(peer_socket, peer_id))
                        thread.daemon = True
                        thread.start()
                        
                        print(f"Connection established with peer {peer_id}")
                    else:
                        print(f"Unknown peer {peer_id} tried to connect")
                        peer_socket.close()
                else:
                    print("Invalid peer connection attempt")
                    peer_socket.close()
                    
            except Exception as e:
                print(f"Error accepting peer: {str(e)}")
    
    def handle_pka_messages(self):
        while True:
            try:
                data = self.pka_socket.recv(4096).decode()
                if not data:
                    break
                    
                if data.startswith("NEW:"):
                    try:
                        # Parse and decrypt the client data
                        encrypted_package = json.loads(data[4:])
                        client_data = self.handle_encrypted_client_data(encrypted_package)
                        
                        if client_data:
                            if self.verify_client_key(
                                client_data['client_id'],
                                client_data['public_key'],
                                client_data['signature']
                            ):
                                self.add_peer(client_data['client_id'], {
                                    'public_key': client_data['public_key'],
                                    'peer_port': client_data['peer_port']
                                })
                                print(f"Added new verified peer: {client_data['client_id']}")
                            else:
                                print(f"Warning: Invalid signature for new peer {client_data['client_id']}")
                                
                    except Exception as e:
                        print(f"Error processing new client: {str(e)}")
                        
                elif data.startswith("DISC:"):
                    disc_data = json.loads(data[5:])
                    client_id = disc_data['client_id']
                    if client_id in self.peer_connections:
                        del self.peer_connections[client_id]
                    print(f"\nClient disconnected: {client_id}")
                    
            except Exception as e:
                print(f"Error in PKA message handler: {str(e)}")
                break
                
        print("\nDisconnected from PKA")

    def handle_encrypted_client_data(self, encrypted_package):
        """Helper method to decrypt and process hybrid-encrypted client data"""
        try:
            if not isinstance(encrypted_package, dict):
                # Try parsing as JSON if it's a string
                try:
                    encrypted_package = json.loads(encrypted_package)
                except:
                    raise Exception("Invalid encrypted package format")

            # Make sure we have the required fields
            if 'key' not in encrypted_package or 'data' not in encrypted_package:
                raise Exception("Missing required fields in encrypted package")

            # Decrypt the DES key using RSA
            des_key = self.rsa.decrypt_key(encrypted_package['key'], self.rsa.private_key)
            
            # Remove any JSON artifacts from the key
            if isinstance(des_key, str):
                try:
                    des_key = json.loads(des_key)
                except:
                    pass

            # Decrypt the actual data using DES
            decrypted_str = des_decrypt(encrypted_package['data'], des_key)
            
            # Parse and return the decrypted data
            try:
                return json.loads(decrypted_str)
            except:
                return decrypted_str
                
        except Exception as e:
            print(f"Error decrypting client data: {str(e)}")
            raise

    def register_with_pka(self, host, port):
        try:
            self.pka_socket.connect((host, port))
            
            # Receive PKA's public key
            data = self.pka_socket.recv(4096).decode()
            if not data.startswith("PKA:"):
                raise Exception("Invalid PKA key format")
                
            pka_key_data = json.loads(data[4:])
            self.pka_public_key = (int(pka_key_data['e']), int(pka_key_data['n']))
            print("Received PKA public key")
            
            # Send registration data
            reg_data = {
                'client_id': self.client_id,
                'public_key': {
                    'e': str(self.rsa.public_key[0]),
                    'n': str(self.rsa.public_key[1])
                },
                'peer_port': self.peer_port
            }
            self.pka_socket.send(f"REG:{json.dumps(reg_data)}".encode())
            
            # Receive acknowledgment
            response = self.pka_socket.recv(4096).decode()
            if response.startswith("ACK:"):
                ack_data = json.loads(response[4:])
                self.signature = ack_data['signature']
                
                # Process other clients
                for client_id, encrypted_package in ack_data['other_clients'].items():
                    try:
                        client_data = self.handle_encrypted_client_data(encrypted_package)
                        if client_data:
                            self.add_peer(client_id, {
                                'public_key': client_data['public_key'],
                                'peer_port': client_data['peer_port']
                            })
                            print(f"Added verified peer: {client_id}")
                    except Exception as e:
                        print(f"Error processing peer {client_id}: {str(e)}")
                        continue
                
                thread = threading.Thread(target=self.handle_pka_messages)
                thread.daemon = True
                thread.start()
                
                return True
                
            return False
            
        except Exception as e:
            print(f"Registration error: {str(e)}")
            return False
    
    def add_peer(self, client_id, info):
        public_key = (int(info['public_key']['e']), int(info['public_key']['n']))
        peer_port = info.get('peer_port')
        self.peer_connections[client_id] = {
            'socket': None,
            'public_key': public_key,
            'peer_port': peer_port,
            'des_key': generate_random_key()
        }
        print(f"Added/updated peer {client_id} with port {peer_port}")
    
    def connect_to_peer(self, client_id):
        if client_id not in self.peer_connections:
            print(f"Unknown peer {client_id}")
            return False
            
        peer_info = self.peer_connections[client_id]
        if peer_info['socket'] is None:
            try:
                peer_socket = socket.socket()
                peer_port = peer_info['peer_port']
                if not peer_port:
                    print(f"No port information for peer {client_id}")
                    return False
                    
                peer_socket.connect((self.host, peer_port))
                
                peer_data = {
                    'client_id': self.client_id,
                    'peer_port': self.peer_port
                }
                peer_socket.send(f"PEER:{json.dumps(peer_data)}".encode())
                
                peer_info['socket'] = peer_socket
                thread = threading.Thread(target=self.handle_peer_messages,
                                       args=(peer_socket, client_id))
                thread.daemon = True
                thread.start()
                
                self.send_des_key(client_id)
                print(f"Successfully connected to peer {client_id}")
                return True
                
            except Exception as e:
                print(f"Error connecting to peer {client_id}: {str(e)}")
                return False
        return True
    
    def send_des_key(self, peer_id):
        """Send DES key encrypted with both sender's private key and receiver's public key"""
        peer_info = self.peer_connections[peer_id]
        try:
            print(f"\n[SECURE KEY EXCHANGE WITH PEER {peer_id}]")
            print("1. Generating new DES key for secure communication")
            print(f"2. Using sender's (Client {self.client_id}) keys for first encryption:")
            print(f"   Private Key (d): {self.rsa.private_key[0]}")
            print(f"   Private Key (n): {self.rsa.private_key[1]}")
            print(f"3. Using receiver's (Client {peer_id}) keys for second encryption:")
            print(f"   Public Key (e): {peer_info['public_key'][0]}")
            print(f"   Public Key (n): {peer_info['public_key'][1]}")
            
            # Double encrypt the DES key
            print("4. Performing double encryption:")
            print("   - First encryption: Using sender's private key (for authentication)")
            print("   - Second encryption: Using receiver's public key (for confidentiality)")
            
            encrypted_key = self.rsa.encrypt_key_double(
                peer_info['des_key'],
                self.rsa.private_key,
                peer_info['public_key']
            )
            
            print("5. Double encryption completed successfully")
            key_message = {'key': encrypted_key}
            peer_info['socket'].send(f"KEY:{json.dumps(key_message)}".encode())
            print("6. Encrypted DES key sent successfully")
            
        except Exception as e:
            print(f"Error in secure key exchange: {str(e)}")
    
    def send_message(self, peer_id, message):
        if peer_id not in self.peer_connections:
            print(f"Unknown peer {peer_id}")
            return
            
        if not self.connect_to_peer(peer_id):
            print(f"Failed to connect to peer {peer_id}")
            return
            
        try:
            peer_info = self.peer_connections[peer_id]
            encrypted_msg = des_encrypt(message, peer_info['des_key'])
            peer_info['socket'].send(f"MSG:{encrypted_msg}".encode())
            print("Message sent successfully")
        except Exception as e:
            print(f"Error sending message to {peer_id}: {str(e)}")
    
    def handle_peer_messages(self, peer_socket, peer_id):
        while True:
            try:
                data = peer_socket.recv(4096).decode()
                if not data:
                    break
                    
                if data.startswith("MSG:"):
                    encrypted_msg = data[4:]
                    decrypted = des_decrypt(encrypted_msg, self.peer_connections[peer_id]['des_key'])
                    print(f"\nFrom {peer_id}: {decrypted}")
                    
                elif data.startswith("KEY:"):
                    key_data = json.loads(data[4:])
                    # Double decrypt the DES key:
                    # 1. First with receiver's private key (ourselves)
                    # 2. Then with sender's public key (for verification)
                    peer_public_key = self.peer_connections[peer_id]['public_key']
                    decrypted_key = self.rsa.decrypt_key_double(
                        key_data['key'],
                        peer_public_key,  # sender's public key for verification
                        self.rsa.private_key  # our private key for decryption
                    )
                    self.peer_connections[peer_id]['des_key'] = decrypted_key
                    print(f"Securely received and verified DES key from {peer_id}")
                    
            except Exception as e:
                print(f"Error handling peer message from {peer_id}: {str(e)}")
                break
        
        self.peer_connections[peer_id]['socket'] = None
        print(f"\nDisconnected from peer {peer_id}")
    
    def handle_messages(self):
        print("\nAvailable commands:")
        print("list - Show online peers")
        print("connect <peer_id> - Connect to a peer")
        print("msg <peer_id> <message> - Send message to peer")
        print("exit - Quit application")
        
        try:
            while True:
                command = input("\nEnter command: ").strip()
                if not command:
                    continue
                    
                if command == "list":
                    print("\nOnline peers:")
                    for peer_id in self.peer_connections:
                        status = "Connected" if self.peer_connections[peer_id]['socket'] else "Not connected"
                        print(f"{peer_id}: {status}")
                        
                elif command.startswith("connect "):
                    peer_id = command[8:].strip()
                    if self.connect_to_peer(peer_id):
                        print(f"Connected to {peer_id}")
                    else:
                        print(f"Failed to connect to {peer_id}")
                        
                elif command.startswith("msg "):
                    parts = command[4:].strip().split(" ", 1)
                    if len(parts) != 2:
                        print("Usage: msg <peer_id> <message>")
                        continue
                    peer_id, message = parts
                    self.send_message(peer_id, message)
                    
                elif command == "exit":
                    break
                    
                else:
                    print("Unknown command")
                    
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.cleanup()
    
    def cleanup(self):
        for peer_info in self.peer_connections.values():
            if peer_info['socket']:
                try:
                    peer_info['socket'].close()
                except:
                    pass
                    
        try:
            self.pka_socket.close()
        except:
            pass
            
        try:
            self.peer_server.close()
        except:
            pass

def main():
    client = P2PClient()
    host = socket.gethostname()
    port = 5000
    
    print("Connecting to PKA server...")
    client.start(host, port)

if __name__ == "__main__":
    main()