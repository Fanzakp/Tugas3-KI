import random
import math
import base64
import hashlib
import json

class RSA:
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        
    def is_prime(self, n, k=5):
        if n == 2 or n == 3:
            return True
        if n < 2 or n % 2 == 0:
            return False
            
        r = 0
        d = n - 1
        while d % 2 == 0:
            r += 1
            d //= 2
            
        for _ in range(k):
            a = random.randrange(2, n-1)
            x = pow(a, d, n)
            if x == 1 or x == n-1:
                continue
            for _ in range(r-1):
                x = pow(x, 2, n)
                if x == n-1:
                    break
            else:
                return False
        return True
        
    def generate_prime(self, bits):
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            if self.is_prime(n):
                return n
            
    def generate_prime_e(self, phi):
        """
        Generate a suitable public exponent e that is:
        1. Coprime with phi
        2. 1 < e < phi
        3. Typically a prime number for better security
        """
        while True:
            # Generate a random odd number in a reasonable range
            e = random.getrandbits(32) | (1 << 16) | 1
            
            # Must be less than phi and greater than 1
            if e >= phi:
                continue
                
            # Check if it's probably prime using existing is_prime
            if not self.is_prime(e, k=5):
                continue
                
            # Check if it's coprime with phi
            if math.gcd(e, phi) == 1:
                return e
                
    def extended_gcd(self, a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
        
    def mod_inverse(self, e, phi):
        gcd, x, _ = self.extended_gcd(e, phi)
        if gcd != 1:
            raise Exception("Modular inverse does not exist")
        return x % phi
        
    def generate_keys(self):
        """
        Generate public and private key pairs with dynamic public exponent e
        """
        bits = self.key_size // 2
        
        # Generate two distinct prime numbers using existing generate_prime
        p = self.generate_prime(bits)
        q = self.generate_prime(bits)
        while p == q:  # Ensure p and q are different
            q = self.generate_prime(bits)
        
        n = p * q
        phi = (p - 1) * (q - 1)
        
        # Generate public exponent e dynamically
        e = self.generate_prime_e(phi)
        
        # Calculate private exponent d
        d = self.mod_inverse(e, phi)
        
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        # Validation check
        test_message = random.getrandbits(64)
        encrypted = pow(test_message, e, n)
        decrypted = pow(encrypted, d, n)
        if test_message != decrypted:
            # If validation fails, regenerate keys
            return self.generate_keys()

    def sign(self, message):
        """
        Sign a message using private key
        Returns base64 encoded signature
        """
        if isinstance(message, str):
            message = message.encode()
            
        # Create message hash
        message_hash = hashlib.sha256(message).digest()
        hash_int = int.from_bytes(message_hash, byteorder='big')
        
        # Sign hash
        d, n = self.private_key
        signature = pow(hash_int, d, n)
        
        # Convert to base64
        sig_bytes = signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
        return base64.b64encode(sig_bytes).decode()

    def verify_signature(self, message, signature, public_key):
        """
        Verify signature using public key
        """
        if isinstance(message, str):
            message = message.encode()
        if isinstance(signature, str):
            signature = base64.b64decode(signature)
            
        # Get hash of original message
        message_hash = hashlib.sha256(message).digest()
        hash_int = int.from_bytes(message_hash, byteorder='big')
        
        # Convert signature to int
        sig_int = int.from_bytes(signature, byteorder='big')
        
        # Verify
        e, n = public_key
        decrypted_hash = pow(sig_int, e, n)
        
        return decrypted_hash == hash_int

    def encrypt_key(self, key_string, public_key):
        """Original single encryption using RSA public key"""
        try:
            # Standardize the input format
            if not isinstance(key_string, str):
                key_string = json.dumps(key_string, ensure_ascii=False)
            
            # Add a marker at the start of the JSON
            marked_string = "JSON_START:" + key_string
            
            # Convert string to bytes using UTF-8
            key_bytes = marked_string.encode('utf-8')
            
            # Calculate maximum chunk size
            e, n = public_key
            max_chunk_size = (n.bit_length() - 88) // 8  # Safe margin for PKCS#1 v1.5
            
            # Split into chunks
            chunks = [key_bytes[i:i + max_chunk_size] for i in range(0, len(key_bytes), max_chunk_size)]
            encrypted_chunks = []
            
            # Encrypt each chunk
            for chunk in chunks:
                chunk_int = int.from_bytes(chunk, byteorder='big')
                encrypted_int = pow(chunk_int, e, n)
                encrypted_bytes = encrypted_int.to_bytes((encrypted_int.bit_length() + 7) // 8, byteorder='big')
                encrypted_chunks.append(base64.b64encode(encrypted_bytes).decode('ascii'))
            
            # Join chunks with a delimiter
            return "##CHUNK##".join(encrypted_chunks)
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise

    def decrypt_key_raw(self, encrypted_data, private_key):
        """Original raw decryption using RSA private key"""
        try:
            # Decode base64
            if isinstance(encrypted_data, str):
                encrypted_bytes = base64.b64decode(encrypted_data.encode('ascii'))
            else:
                encrypted_bytes = encrypted_data
            
            print(f"Decrypting data of length: {len(encrypted_bytes)} bytes")
            
            # Decrypt the bytes
            encrypted_int = int.from_bytes(encrypted_bytes, byteorder='big')
            d, n = private_key
            decrypted_int = pow(encrypted_int, d, n)
            
            # Convert to bytes with proper padding
            byte_length = (decrypted_int.bit_length() + 7) // 8
            decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
            
            # Look for our marker
            marker = b"JSON_START:"
            start_idx = decrypted_bytes.find(marker)
            
            if start_idx >= 0:
                # Extract the actual JSON data after the marker
                json_bytes = decrypted_bytes[start_idx + len(marker):]
                print(f"Found JSON data of length: {len(json_bytes)} bytes")
                return json_bytes
            else:
                print("Warning: JSON_START marker not found in decrypted data")
                return decrypted_bytes
                
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

    def decrypt_key(self, encrypted_data, private_key):
        """Original decryption using RSA private key with chunking support"""
        try:
            # Split the chunks
            encrypted_chunks = encrypted_data.split("##CHUNK##")
            decrypted_parts = []
            
            # Decrypt each chunk
            for chunk in encrypted_chunks:
                # Decode base64
                encrypted_bytes = base64.b64decode(chunk.encode('ascii'))
                
                # Decrypt the bytes
                encrypted_int = int.from_bytes(encrypted_bytes, byteorder='big')
                d, n = private_key
                decrypted_int = pow(encrypted_int, d, n)
                
                # Convert to bytes with proper padding
                byte_length = (decrypted_int.bit_length() + 7) // 8
                decrypted_bytes = decrypted_int.to_bytes(byte_length, byteorder='big')
                decrypted_parts.append(decrypted_bytes)
            
            # Combine all decrypted parts
            combined_bytes = b''.join(decrypted_parts)
            
            # Look for our marker
            marker = b"JSON_START:"
            start_idx = combined_bytes.find(marker)
            
            if start_idx >= 0:
                # Extract the actual JSON data after the marker
                json_bytes = combined_bytes[start_idx + len(marker):]
                return json_bytes.decode('utf-8')
            else:
                return combined_bytes.decode('utf-8')
                
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    # Fungsi baru untuk enkripsi ganda
    def encrypt_key_double(self, key_string, private_key_sender, public_key_receiver):
        """Double encryption using sender's private key and receiver's public key"""
        try:
            # Standardize the input format
            if not isinstance(key_string, str):
                key_string = json.dumps(key_string, ensure_ascii=False)
            
            # Add a marker at the start
            marked_string = "JSON_START:" + key_string
            
            # Convert string to bytes using UTF-8
            key_bytes = marked_string.encode('utf-8')
            
            # Calculate maximum chunk size (considering double encryption)
            d_sender, n_sender = private_key_sender
            e_receiver, n_receiver = public_key_receiver
            max_chunk_size = min((n_sender.bit_length() - 88) // 8, (n_receiver.bit_length() - 88) // 8)
            
            # Split into chunks
            chunks = [key_bytes[i:i + max_chunk_size] for i in range(0, len(key_bytes), max_chunk_size)]
            encrypted_chunks = []
            
            # Encrypt each chunk twice
            for chunk in chunks:
                # First encryption with sender's private key
                chunk_int = int.from_bytes(chunk, byteorder='big')
                first_encrypted = pow(chunk_int, d_sender, n_sender)
                
                # Second encryption with receiver's public key
                second_encrypted = pow(first_encrypted, e_receiver, n_receiver)
                
                # Convert to bytes and encode
                encrypted_bytes = second_encrypted.to_bytes(
                    (second_encrypted.bit_length() + 7) // 8, 
                    byteorder='big'
                )
                encrypted_chunks.append(base64.b64encode(encrypted_bytes).decode('ascii'))
            
            # Join chunks with a delimiter
            return "##CHUNK##".join(encrypted_chunks)
            
        except Exception as e:
            print(f"Double encryption error: {str(e)}")
            raise

    def decrypt_key_double(self, encrypted_data, public_key_sender, private_key_receiver):
        """Double decryption using sender's public key and receiver's private key"""
        try:
            # Split the chunks
            encrypted_chunks = encrypted_data.split("##CHUNK##")
            decrypted_parts = []
            
            # Decrypt each chunk
            for chunk in encrypted_chunks:
                # Decode base64
                encrypted_bytes = base64.b64decode(chunk.encode('ascii'))
                encrypted_int = int.from_bytes(encrypted_bytes, byteorder='big')
                
                # First decryption with receiver's private key
                d_receiver, n_receiver = private_key_receiver
                first_decrypted = pow(encrypted_int, d_receiver, n_receiver)
                
                # Second decryption with sender's public key
                e_sender, n_sender = public_key_sender
                second_decrypted = pow(first_decrypted, e_sender, n_sender)
                
                # Convert to bytes with proper padding
                byte_length = (second_decrypted.bit_length() + 7) // 8
                decrypted_bytes = second_decrypted.to_bytes(byte_length, byteorder='big')
                decrypted_parts.append(decrypted_bytes)
            
            # Combine all decrypted parts
            combined_bytes = b''.join(decrypted_parts)
            
            # Look for our marker
            marker = b"JSON_START:"
            start_idx = combined_bytes.find(marker)
            
            if start_idx >= 0:
                json_bytes = combined_bytes[start_idx + len(marker):]
                return json_bytes.decode('utf-8')
            else:
                return combined_bytes.decode('utf-8')
                
        except Exception as e:
            raise Exception(f"Double decryption failed: {str(e)}")
        
def main():
    # Test RSA implementation
    rsa = RSA(key_size=2048)
    print("Generating RSA keys...")
    rsa.generate_keys()
    print("Public key:", rsa.public_key)
    print("Private key:", rsa.private_key)
    
    # Test key encryption/decryption
    test_key = "TestKey123"
    print("\nOriginal key:", test_key)
    
    encrypted = rsa.encrypt_key(test_key, rsa.public_key)
    print("Encrypted key:", encrypted)
    
    decrypted = rsa.decrypt_key(encrypted, rsa.private_key)
    print("Decrypted key:", decrypted)

if __name__ == "__main__":
    main()