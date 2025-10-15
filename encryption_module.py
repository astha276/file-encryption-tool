# Import required libraries
from cryptography.fernet import Fernet
import os
import hashlib

# Create our main encryption class
class FileEncryptor:
    def __init__(self):
        """Initialize the FileEncryptor class"""
        self.key = None          # Will store our encryption key
        self.fernet = None       # Will store our encryption object
        print("FileEncryptor initialized successfully!")
    
    def generate_key(self):
        """Generate a new encryption key"""
        print("Generating new encryption key...")
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        print("✅ New encryption key generated!")
        return self.key
    
    def save_key(self, key_filename):
        """Save the encryption key to a file"""
        if self.key is None:
            print("❌ No key to save! Generate a key first.")
            return False
        
        try:
            with open(key_filename, 'wb') as key_file:
                key_file.write(self.key)
            print(f"✅ Key saved to: {key_filename}")
            return True
        except Exception as e:
            print(f"❌ Error saving key: {e}")
            return False
    
    def load_key(self, key_filename):
        """Load encryption key from a file"""
        try:
            with open(key_filename, 'rb') as key_file:
                self.key = key_file.read()
            self.fernet = Fernet(self.key)
            print(f"✅ Key loaded from: {key_filename}")
            return True
        except FileNotFoundError:
            print(f"❌ Key file '{key_filename}' not found!")
            return False
        except Exception as e:
            print(f"❌ Error loading key: {e}")
            return False
    def encrypt_file(self, input_filename, output_filename=None):
        """Encrypt a file"""
        # Check if we have a key
        if self.key is None or self.fernet is None:
            print("❌ No encryption key loaded! Generate or load a key first.")
            return False
        
        # Check if input file exists
        if not os.path.exists(input_filename):
            print(f"❌ File '{input_filename}' not found!")
            return False
        
        # Determine output filename
        if output_filename is None:
            output_filename = input_filename + '.encrypted'
        
        try:
            print(f"🔒 Encrypting file: {input_filename}")
            
            # Read the original file
            with open(input_filename, 'rb') as file:
                original_data = file.read()
            
            # Encrypt the data
            encrypted_data = self.fernet.encrypt(original_data)
            
            # Write encrypted data to new file
            with open(output_filename, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            print(f"✅ File encrypted successfully!")
            print(f"   Original: {input_filename}")
            print(f"   Encrypted: {output_filename}")
            return output_filename
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return False
    def decrypt_file(self, encrypted_filename, output_filename=None):
        """Decrypt a file"""
        # Check if we have a key
        if self.key is None or self.fernet is None:
            print("❌ No decryption key loaded! Load the correct key first.")
            return False
        
        # Check if encrypted file exists
        if not os.path.exists(encrypted_filename):
            print(f"❌ Encrypted file '{encrypted_filename}' not found!")
            return False
        
        # Determine output filename
        if output_filename is None:
            if encrypted_filename.endswith('.encrypted'):
                output_filename = encrypted_filename[:-10]  # Remove .encrypted
            else:
                output_filename = encrypted_filename + '.decrypted'
        
        try:
            print(f"🔓 Decrypting file: {encrypted_filename}")
            
            # Read the encrypted file
            with open(encrypted_filename, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            # Decrypt the data
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Write decrypted data to new file
            with open(output_filename, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            print(f"✅ File decrypted successfully!")
            print(f"   Encrypted: {encrypted_filename}")
            print(f"   Decrypted: {output_filename}")
            return output_filename
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            print("   This could mean:")
            print("   - Wrong encryption key")
            print("   - Corrupted file")
            print("   - File wasn't encrypted with this tool")
            return False

# Test our class
# Test our complete encryption system
if __name__ == "__main__":
    print("=== Complete File Encryption Test ===")
    
    # Create an instance of our class
    encryptor = FileEncryptor()
    
    # Step 1: Generate and save a key
    print("\n--- Step 1: Key Generation ---")
    encryptor.generate_key()
    encryptor.save_key("my_encryption_key.key")
    
    # Step 2: Encrypt a file
    print("\n--- Step 2: File Encryption ---")
    encrypted_file = encryptor.encrypt_file("test_document.txt")
    
    if encrypted_file:
        # Step 3: Create a new encryptor to test key loading
        print("\n--- Step 3: Testing Key Loading ---")
        new_encryptor = FileEncryptor()
        new_encryptor.load_key("my_encryption_key.key")
        
        # Step 4: Decrypt the file
        print("\n--- Step 4: File Decryption ---")
        decrypted_file = new_encryptor.decrypt_file(encrypted_file)
        
        if decrypted_file:
            print("\n--- Step 5: Verification ---")
            print("Let's verify the decryption worked by reading both files:")
            
            # Read original file
            with open("test_document.txt", 'r') as f:
                original_content = f.read()
            
            # Read decrypted file
            with open(decrypted_file, 'r') as f:
                decrypted_content = f.read()
            
            if original_content == decrypted_content:
                print("✅ SUCCESS! Original and decrypted files are identical!")
                print("🎉 Your encryption tool is working perfectly!")
            else:
                print("❌ ERROR: Files don't match!")
    
    print("\n=== Test Complete ===")

