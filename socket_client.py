import socket
import threading
from des_implementation import des_encrypt, des_decrypt
import base64

class SecureChatClient:
    def __init__(self):
        self.socket = socket.socket()
        self.encryption_key = None
        
    def connect(self, host, port):
        """Connect to the server"""
        self.socket.connect((host, port))
        # Receive encryption key from server
        initial_data = self.socket.recv(1024).decode()
        if initial_data.startswith("KEY:"):
            self.encryption_key = initial_data[4:]  # Remove "KEY:" prefix
            print(f"Received encryption key from server: {self.encryption_key}")
        
    def receive_messages(self):
        """Handle receiving messages"""
        while True:
            try:
                # Receive data from server
                data = self.socket.recv(4096).decode()
                
                # Handle different message types
                if data.startswith("SYS:"):
                    print(f"\nSystem: {data[4:]}")  # Remove "SYS:" prefix
                    continue
                elif data.startswith("MSG:"):
                    encrypted_msg = data[4:]  # Remove "MSG:" prefix
                    try:
                        decrypted_msg = des_decrypt(encrypted_msg, self.encryption_key)
                        print(f"\nReceived encrypted message: {encrypted_msg}")
                        print(f"Decrypted message: {decrypted_msg}")
                    except Exception as e:
                        print(f"\nDecryption error: {e}")
                        print(f"Failed to decrypt message: {encrypted_msg}")
                        
            except Exception as e:
                print(f"\nConnection error: {e}")
                break
                
    def send_message(self, message):
        """Encrypt and send message"""
        try:
            encrypted_msg = des_encrypt(message, self.encryption_key)
            formatted_msg = f"MSG:{encrypted_msg}"
            print(f"\nOriginal message: {message}")
            print(f"Encrypted message: {encrypted_msg}")
            self.socket.send(formatted_msg.encode())
        except Exception as e:
            print(f"Encryption error: {e}")
        
    def start(self):
        """Start the chat client"""
        # Start receiving thread
        receive_thread = threading.Thread(target=self.receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        
        # Main sending loop
        try:
            while True:
                message = input("\nEnter message (or 'exit' to quit): ")
                if message.lower() == 'exit':
                    break
                self.send_message(message)
        except KeyboardInterrupt:
            print("\nExiting...")
        finally:
            self.socket.close()

def main():
    client = SecureChatClient()
    host = socket.gethostname()
    port = 5000
    
    print("Connecting to server...")
    client.connect(host, port)
    client.start()

if __name__ == '__main__':
    main()