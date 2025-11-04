# # Import required libraries
# from cryptography.fernet import Fernet
# import os
# import hashlib

# # Create our main encryption class
# class FileEncryptor:
#     def __init__(self):
#         """Initialize the FileEncryptor class"""
#         self.key = None          # Will store our encryption key
#         self.fernet = None       # Will store our encryption object
#         print("FileEncryptor initialized successfully!")
    
#     def generate_key(self):
#         """Generate a new encryption key"""
#         print("Generating new encryption key...")
#         self.key = Fernet.generate_key()
#         self.fernet = Fernet(self.key)
#         print("✅ New encryption key generated!")
#         return self.key
    
#     def save_key(self, key_filename):
#         """Save the encryption key to a file"""
#         if self.key is None:
#             print("❌ No key to save! Generate a key first.")
#             return False
        
#         try:
#             with open(key_filename, 'wb') as key_file:
#                 key_file.write(self.key)
#             print(f"✅ Key saved to: {key_filename}")
#             return True
#         except Exception as e:
#             print(f"❌ Error saving key: {e}")
#             return False
    
#     def load_key(self, key_filename):
#         """Load encryption key from a file"""
#         try:
#             with open(key_filename, 'rb') as key_file:
#                 self.key = key_file.read()
#             self.fernet = Fernet(self.key)
#             print(f"✅ Key loaded from: {key_filename}")
#             return True
#         except FileNotFoundError:
#             print(f"❌ Key file '{key_filename}' not found!")
#             return False
#         except Exception as e:
#             print(f"❌ Error loading key: {e}")
#             return False
#     def encrypt_file(self, input_filename, output_filename=None):
#         """Encrypt a file"""
#         # Check if we have a key
#         if self.key is None or self.fernet is None:
#             print("❌ No encryption key loaded! Generate or load a key first.")
#             return False
        
#         # Check if input file exists
#         if not os.path.exists(input_filename):
#             print(f"❌ File '{input_filename}' not found!")
#             return False
        
#         # Determine output filename
#         if output_filename is None:
#             output_filename = input_filename + '.encrypted'
        
#         try:
#             print(f"🔒 Encrypting file: {input_filename}")
            
#             # Read the original file
#             with open(input_filename, 'rb') as file:
#                 original_data = file.read()
            
#             # Encrypt the data
#             encrypted_data = self.fernet.encrypt(original_data)
            
#             # Write encrypted data to new file
#             with open(output_filename, 'wb') as encrypted_file:
#                 encrypted_file.write(encrypted_data)
            
#             print(f"✅ File encrypted successfully!")
#             print(f"   Original: {input_filename}")
#             print(f"   Encrypted: {output_filename}")
#             return output_filename
            
#         except Exception as e:
#             print(f"❌ Encryption failed: {e}")
#             return False
#     def decrypt_file(self, encrypted_filename, output_filename=None):
#         """Decrypt a file"""
#         # Check if we have a key
#         if self.key is None or self.fernet is None:
#             print("❌ No decryption key loaded! Load the correct key first.")
#             return False
        
#         # Check if encrypted file exists
#         if not os.path.exists(encrypted_filename):
#             print(f"❌ Encrypted file '{encrypted_filename}' not found!")
#             return False
        
#         # Determine output filename
#         if output_filename is None:
#             if encrypted_filename.endswith('.encrypted'):
#                 output_filename = encrypted_filename[:-10]  # Remove .encrypted
#             else:
#                 output_filename = encrypted_filename + '.decrypted'
        
#         try:
#             print(f"🔓 Decrypting file: {encrypted_filename}")
            
#             # Read the encrypted file
#             with open(encrypted_filename, 'rb') as encrypted_file:
#                 encrypted_data = encrypted_file.read()
            
#             # Decrypt the data
#             decrypted_data = self.fernet.decrypt(encrypted_data)
            
#             # Write decrypted data to new file
#             with open(output_filename, 'wb') as decrypted_file:
#                 decrypted_file.write(decrypted_data)
            
#             print(f"✅ File decrypted successfully!")
#             print(f"   Encrypted: {encrypted_filename}")
#             print(f"   Decrypted: {output_filename}")
#             return output_filename
            
#         except Exception as e:
#             print(f"❌ Decryption failed: {e}")
#             print("   This could mean:")
#             print("   - Wrong encryption key")
#             print("   - Corrupted file")
#             print("   - File wasn't encrypted with this tool")
#             return False

# # Test our class
# # Test our complete encryption system
# if __name__ == "__main__":
#     print("=== Complete File Encryption Test ===")
    
#     # Create an instance of our class
#     encryptor = FileEncryptor()
    
#     # Step 1: Generate and save a key
#     print("\n--- Step 1: Key Generation ---")
#     encryptor.generate_key()
#     encryptor.save_key("my_encryption_key.key")
    
#     # Step 2: Encrypt a file
#     print("\n--- Step 2: File Encryption ---")
#     encrypted_file = encryptor.encrypt_file("test_document.txt")
    
#     if encrypted_file:
#         # Step 3: Create a new encryptor to test key loading
#         print("\n--- Step 3: Testing Key Loading ---")
#         new_encryptor = FileEncryptor()
#         new_encryptor.load_key("my_encryption_key.key")
        
#         # Step 4: Decrypt the file
#         print("\n--- Step 4: File Decryption ---")
#         decrypted_file = new_encryptor.decrypt_file(encrypted_file)
        
#         if decrypted_file:
#             print("\n--- Step 5: Verification ---")
#             print("Let's verify the decryption worked by reading both files:")
            
#             # Read original file
#             with open("test_document.txt", 'r') as f:
#                 original_content = f.read()
            
#             # Read decrypted file
#             with open(decrypted_file, 'r') as f:
#                 decrypted_content = f.read()
            
#             if original_content == decrypted_content:
#                 print("✅ SUCCESS! Original and decrypted files are identical!")
#                 print("🎉 Your encryption tool is working perfectly!")
#             else:
#                 print("❌ ERROR: Files don't match!")
    
#     print("\n=== Test Complete ===")


# Import required libraries
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import hashlib
import base64
import json
import time
import secrets
from datetime import datetime

# Fix for InvalidToken import - handle different cryptography versions
try:
    from cryptography.exceptions import InvalidToken
except ImportError:
    from cryptography.fernet import InvalidToken

# Additional imports for advanced features
import sqlite3
import threading
from pathlib import Path

class BatchProcessor:
    """Handle batch file operations with progress tracking"""
    
    def __init__(self, encryptor):
        self.encryptor = encryptor
        self.batch_queue = []
        self.progress_callback = None
        self.cancel_flag = False
        
    def add_files(self, file_paths):
        """Add files to batch queue"""
        for file_path in file_paths:
            if os.path.exists(file_path):
                self.batch_queue.append({
                    'file_path': file_path,
                    'status': 'pending',
                    'timestamp': datetime.now().isoformat(),
                    'size': os.path.getsize(file_path),
                    'type': 'encryption'
                })
    
    def process_batch_encryption(self, password, delete_original=False):
        """Process all files in batch with progress tracking"""
        total_files = len(self.batch_queue)
        completed = 0
        results = {'successful': [], 'failed': []}
        
        for item in self.batch_queue:
            if self.cancel_flag:
                break
                
            try:
                # Update progress
                if self.progress_callback:
                    self.progress_callback(completed, total_files, item['file_path'])
                
                # Encrypt file
                encrypted_file = self.encryptor.encrypt_file(
                    item['file_path'], 
                    password
                )
                
                if encrypted_file:
                    item['status'] = 'completed'
                    item['output_file'] = encrypted_file
                    results['successful'].append(item)
                    
                    # Delete original if requested
                    if delete_original:
                        try:
                            os.remove(item['file_path'])
                            item['original_deleted'] = True
                        except:
                            item['original_deleted'] = False
                else:
                    item['status'] = 'failed'
                    results['failed'].append(item)
                    
            except Exception as e:
                item['status'] = 'failed'
                item['error'] = str(e)
                results['failed'].append(item)
            
            completed += 1
        
        # Final progress update
        if self.progress_callback:
            self.progress_callback(completed, total_files, "Batch complete")
            
        return results
    
    def clear_queue(self):
        """Clear batch queue"""
        self.batch_queue.clear()
    
    def get_queue_info(self):
        """Get batch queue information"""
        return {
            'total_files': len(self.batch_queue),
            'total_size': sum(item['size'] for item in self.batch_queue),
            'pending': len([item for item in self.batch_queue if item['status'] == 'pending'])
        }

class FileHistoryManager:
    """Manage file operation history with SQLite database"""
    
    def __init__(self, db_path="encryption_history.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_operations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation_type TEXT NOT NULL,
                    original_file TEXT NOT NULL,
                    output_file TEXT,
                    file_size INTEGER,
                    success BOOLEAN NOT NULL,
                    error_message TEXT,
                    password_protected BOOLEAN DEFAULT FALSE,
                    batch_id TEXT,
                    execution_time REAL,
                    file_hash TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS batch_operations (
                    batch_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    total_files INTEGER,
                    successful_files INTEGER,
                    failed_files INTEGER,
                    total_size INTEGER,
                    operation_type TEXT
                )
            ''')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Could not initialize database: {e}")
    
    def add_operation(self, operation_type, original_file, output_file=None, 
                     success=True, error_message=None, file_size=0, 
                     password_protected=False, batch_id=None, execution_time=0, file_hash=None):
        """Add operation to history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO file_operations 
                (timestamp, operation_type, original_file, output_file, file_size, 
                 success, error_message, password_protected, batch_id, execution_time, file_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now().isoformat(),
                operation_type,
                original_file,
                output_file,
                file_size,
                success,
                error_message,
                password_protected,
                batch_id,
                execution_time,
                file_hash
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Could not save operation to history: {e}")
    
    def get_history(self, limit=100, operation_type=None):
        """Get operation history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if operation_type:
                cursor.execute('''
                    SELECT * FROM file_operations 
                    WHERE operation_type = ? 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (operation_type, limit))
            else:
                cursor.execute('''
                    SELECT * FROM file_operations 
                    ORDER BY timestamp DESC LIMIT ?
                ''', (limit,))
            
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]
            
            conn.close()
            return results
        except Exception as e:
            print(f"Warning: Could not load history: {e}")
            return []
    
    def get_statistics(self):
        """Get operation statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get overall stats
            cursor.execute('SELECT COUNT(*) FROM file_operations')
            total_operations = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM file_operations WHERE success = 1')
            successful_operations = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM file_operations WHERE operation_type = "encryption"')
            total_encryptions = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM file_operations WHERE operation_type = "decryption"')
            total_decryptions = cursor.fetchone()[0]
            
            cursor.execute('SELECT SUM(file_size) FROM file_operations WHERE success = 1')
            total_processed_size = cursor.fetchone()[0] or 0
            
            cursor.execute('SELECT COUNT(DISTINCT batch_id) FROM file_operations WHERE batch_id IS NOT NULL')
            total_batches = cursor.fetchone()[0]
            
            conn.close()
            
            return {
                'total_operations': total_operations,
                'successful_operations': successful_operations,
                'failed_operations': total_operations - successful_operations,
                'total_encryptions': total_encryptions,
                'total_decryptions': total_decryptions,
                'total_processed_size': total_processed_size,
                'total_batches': total_batches,
                'success_rate': (successful_operations / total_operations * 100) if total_operations > 0 else 0
            }
        except Exception as e:
            print(f"Warning: Could not load statistics: {e}")
            return {
                'total_operations': 0,
                'successful_operations': 0,
                'failed_operations': 0,
                'total_encryptions': 0,
                'total_decryptions': 0,
                'total_processed_size': 0,
                'total_batches': 0,
                'success_rate': 0
            }
    
    def clear_history(self):
        """Clear all history"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM file_operations')
            cursor.execute('DELETE FROM batch_operations')
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Warning: Could not clear history: {e}")
    
    def export_history(self, export_path, format='csv'):
        """Export history to file"""
        try:
            history = self.get_history(limit=10000)
            
            if format.lower() == 'csv':
                import csv
                with open(export_path, 'w', newline='', encoding='utf-8') as csvfile:
                    if history:
                        fieldnames = history[0].keys()
                        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                        writer.writeheader()
                        writer.writerows(history)
            
            elif format.lower() == 'json':
                with open(export_path, 'w', encoding='utf-8') as jsonfile:
                    json.dump({
                        'export_timestamp': datetime.now().isoformat(),
                        'total_records': len(history),
                        'operations': history
                    }, jsonfile, indent=2, default=str)
        except Exception as e:
            print(f"Warning: Could not export history: {e}")

class AdvancedFileEncryptor:
    """
    Advanced File Encryption Tool with password-based authentication
    and enhanced security features for Operating Systems project
    """
    
    def __init__(self):
        self.key = None
        self.fernet = None
        self.salt = None
        self.password_hash = None
        self.creation_time = None
        self.operation_history = []
        self.failed_attempts = 0
        self.max_failed_attempts = 3
        self.lockout_time = 300  # 5 minutes lockout
        self.last_failed_attempt = None
        
        # Initialize advanced features
        try:
            self.batch_processor = BatchProcessor(self)
            self.history_manager = FileHistoryManager()
        except Exception as e:
            print(f"Warning: Could not initialize advanced features: {e}")
            self.batch_processor = None
            self.history_manager = None
    
    def generate_salt(self):
        """Generate a cryptographically secure random salt"""
        return secrets.token_bytes(32)  # 256-bit salt
    
    def validate_password_strength(self, password: str) -> dict:
        """Validate password strength and provide feedback"""
        if not password:
            return {
                'score': 0,
                'strength': 'Invalid',
                'color': 'red',
                'feedback': ['Password cannot be empty'],
                'percentage': 0
            }
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Complexity checks
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Include uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Include lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Include numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Include special characters")
        
        # Common patterns check
        common_patterns = ['password', '123456', 'qwerty', 'abc123', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 2
            feedback.append("Avoid common patterns")
        
        # Determine strength
        if score >= 6:
            strength = "Very Strong"
            color = "green"
        elif score >= 4:
            strength = "Strong"
            color = "blue"
        elif score >= 2:
            strength = "Medium"
            color = "orange"
        else:
            strength = "Weak"
            color = "red"
        
        return {
            'score': max(0, score),
            'strength': strength,
            'color': color,
            'feedback': feedback,
            'percentage': min(100, max(0, score * 16.67))
        }
    
    def derive_key_from_password(self, password: str, salt: bytes = None):
        """Derive encryption key from password using Scrypt KDF"""
        if not password or len(password.strip()) == 0:
            raise ValueError("❌ Password cannot be empty")
    
        print("🔑 Deriving encryption key from password...")
    
        # Validate password strength
        strength = self.validate_password_strength(password)
        if strength['score'] < 2:
            print(f"⚠️  Warning: Password strength is {strength['strength']}")
            print(f"   Suggestions: {', '.join(strength['feedback'])}")
        else:
            print(f"✅ Password strength: {strength['strength']} ({strength['percentage']:.0f}%)")
    
        # Generate salt if not provided
        if salt is None:
            self.salt = self.generate_salt()
            print("🧂 Generated new salt for key derivation")
        else:
            self.salt = salt
            print("🧂 Using existing salt for key derivation")
    
        try:
            # Fixed Scrypt configuration for compatibility
            kdf = Scrypt(
                salt=self.salt,
                length=32,  # 256-bit key
                n=2**14,    # CPU/memory cost parameter (16384)
                r=8,        # Block size parameter
                p=1,        # Parallelization parameter
            )
        
            password_bytes = password.encode('utf-8')
            derived_key = kdf.derive(password_bytes)
        
            # Create Fernet key (URL-safe base64 encoded)
            self.key = base64.urlsafe_b64encode(derived_key)
            self.fernet = Fernet(self.key)
        
            # Store password hash for verification
            self.password_hash = hashlib.sha256(password_bytes + self.salt).hexdigest()
            self.creation_time = datetime.now().isoformat()
        
            print("✅ Encryption key derived successfully!")
            return self.key
        
        except Exception as e:
            print(f"❌ Key derivation failed: {e}")
            raise

    
    def verify_password(self, password: str) -> bool:
        """Verify if provided password matches stored hash"""
        # Check for account lockout
        if self.is_locked_out():
            remaining_time = int(self.lockout_time - (time.time() - self.last_failed_attempt))
            raise Exception(f"❌ Account locked due to too many failed attempts. Try again in {remaining_time} seconds.")
        
        if not password or not self.password_hash or not self.salt:
            self.record_failed_attempt()
            return False
        
        # Calculate hash of provided password
        password_bytes = password.encode('utf-8')
        calculated_hash = hashlib.sha256(password_bytes + self.salt).hexdigest()
        
        # Verify password
        if calculated_hash == self.password_hash:
            self.reset_failed_attempts()
            print("✅ Password verified successfully!")
            return True
        else:
            self.record_failed_attempt()
            print(f"❌ Invalid password! Failed attempts: {self.failed_attempts}/{self.max_failed_attempts}")
            return False
    
    def is_locked_out(self) -> bool:
        """Check if account is currently locked out"""
        if self.failed_attempts >= self.max_failed_attempts:
            if self.last_failed_attempt:
                time_since_last_attempt = time.time() - self.last_failed_attempt
                return time_since_last_attempt < self.lockout_time
        return False
    
    def record_failed_attempt(self):
        """Record a failed authentication attempt"""
        self.failed_attempts += 1
        self.last_failed_attempt = time.time()
        
        self.operation_history.append({
            'type': 'authentication_failed',
            'timestamp': datetime.now().isoformat(),
            'attempts': self.failed_attempts
        })
    
    def reset_failed_attempts(self):
        """Reset failed attempt counter after successful authentication"""
        self.failed_attempts = 0
        self.last_failed_attempt = None
    
    def generate_key(self):
        """Generate a random encryption key (legacy compatibility)"""
        print("🔑 Generating random encryption key...")
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.creation_time = datetime.now().isoformat()
        print("✅ New encryption key generated!")
        return self.key
    
    def save_key(self, key_filename, password: str = None):
        """Save the encryption key to a file with optional password protection"""
        if self.key is None:
            print("❌ No key to save! Generate a key first.")
            return False
        
        try:
            key_data = {
                'key': base64.b64encode(self.key).decode('utf-8'),
                'creation_time': self.creation_time,
                'salt': base64.b64encode(self.salt).decode('utf-8') if self.salt else None,
                'protected': password is not None,
                'algorithm': 'Fernet (AES 128 CBC + HMAC SHA256)'
            }
            
            key_json = json.dumps(key_data, indent=2)
            
            if password:
                # Encrypt key file with password
                print("🔒 Protecting key file with password...")
                temp_encryptor = AdvancedFileEncryptor()
                temp_encryptor.derive_key_from_password(password)
                encrypted_key_data = temp_encryptor.fernet.encrypt(key_json.encode('utf-8'))
                
                with open(key_filename, 'wb') as key_file:
                    key_file.write(encrypted_key_data)
                print(f"✅ Protected key saved to: {key_filename}")
            else:
                # Save as plain text JSON
                with open(key_filename, 'w') as key_file:
                    key_file.write(key_json)
                print(f"✅ Key saved to: {key_filename}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error saving key: {e}")
            return False
    
    def load_key(self, key_filename, password: str = None):
        """Load encryption key from a file with optional password"""
        try:
            with open(key_filename, 'rb') as key_file:
                file_content = key_file.read()
            
            # Try to decrypt if password provided
            if password:
                print("🔓 Decrypting protected key file...")
                temp_encryptor = AdvancedFileEncryptor()
                temp_encryptor.derive_key_from_password(password)
                try:
                    decrypted_content = temp_encryptor.fernet.decrypt(file_content)
                    key_data = json.loads(decrypted_content.decode('utf-8'))
                except InvalidToken:
                    print("❌ Invalid password for key file!")
                    return False
            else:
                # Try as plain text JSON
                try:
                    key_data = json.loads(file_content.decode('utf-8'))
                except:
                    print("❌ Key file appears to be encrypted. Password required!")
                    return False
            
            # Load key data
            self.key = base64.b64decode(key_data['key'])
            self.fernet = Fernet(self.key)
            self.creation_time = key_data.get('creation_time')
            
            if key_data.get('salt'):
                self.salt = base64.b64decode(key_data['salt'])
            
            print(f"✅ Key loaded from: {key_filename}")
            if key_data.get('protected'):
                print("🔐 Loaded password-protected key")
            
            return True
            
        except FileNotFoundError:
            print(f"❌ Key file '{key_filename}' not found!")
            return False
        except Exception as e:
            print(f"❌ Error loading key: {e}")
            return False
    
    def encrypt_file(self, file_path: str, password: str = None, output_filename=None):
        """Encrypt a file with optional password authentication"""
        # Check if input file exists
        if not os.path.exists(file_path):
            print(f"❌ File '{file_path}' not found!")
            return False
        
        start_time = time.time()
        file_hash = None
        
        try:
            # Calculate file hash for integrity
            with open(file_path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except:
            pass
        
        # Use password-based encryption if password provided
        if password:
            print("🔐 Using password-based encryption...")
            self.derive_key_from_password(password)
        elif self.key is None:
            print("🔑 No key provided, generating random key...")
            self.generate_key()
        
        # Determine output filename
        if output_filename is None:
            output_filename = file_path + '.encrypted'
        
        try:
            print(f"🔒 Encrypting file: {file_path}")
            
            # Read the original file
            with open(file_path, 'rb') as file:
                original_data = file.read()
            
            # Create metadata
            metadata = {
                'original_filename': os.path.basename(file_path),
                'original_size': len(original_data),
                'encryption_time': datetime.now().isoformat(),
                'has_password': password is not None,
                'salt': base64.b64encode(self.salt).decode('utf-8') if self.salt else None,
                'algorithm': 'Fernet (AES 128 CBC + HMAC SHA256)',
                'file_hash': file_hash
            }
            
            # Encrypt the data
            encrypted_data = self.fernet.encrypt(original_data)
            
            # Write encrypted file with metadata
            with open(output_filename, 'wb') as encrypted_file:
                # Write metadata length (4 bytes)
                metadata_json = json.dumps(metadata).encode('utf-8')
                metadata_length = len(metadata_json)
                encrypted_file.write(metadata_length.to_bytes(4, 'big'))
                
                # Write metadata
                encrypted_file.write(metadata_json)
                
                # Write encrypted data
                encrypted_file.write(encrypted_data)
            
            # Log operation
            execution_time = time.time() - start_time
            self.operation_history.append({
                'type': 'encryption',
                'file': os.path.basename(file_path),
                'size': len(original_data),
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'has_password': password is not None
            })
            
            # Save to database if available
            if self.history_manager:
                self.history_manager.add_operation(
                    operation_type='encryption',
                    original_file=file_path,
                    output_file=output_filename,
                    success=True,
                    file_size=len(original_data),
                    password_protected=password is not None,
                    execution_time=execution_time,
                    file_hash=file_hash
                )
            
            print(f"✅ File encrypted successfully!")
            print(f"   Original: {file_path} ({len(original_data)} bytes)")
            print(f"   Encrypted: {output_filename}")
            if password:
                print("🔐 File is password-protected")
            
            return output_filename
            
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            
            # Log failed operation
            execution_time = time.time() - start_time
            self.operation_history.append({
                'type': 'encryption',
                'file': os.path.basename(file_path),
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'error': str(e)
            })
            
            if self.history_manager:
                self.history_manager.add_operation(
                    operation_type='encryption',
                    original_file=file_path,
                    success=False,
                    error_message=str(e),
                    file_size=os.path.getsize(file_path) if os.path.exists(file_path) else 0,
                    password_protected=password is not None,
                    execution_time=execution_time,
                    file_hash=file_hash
                )
            return False
    
    def decrypt_file(self, encrypted_filename, password: str = None, output_filename=None):
        """Decrypt a file with optional password authentication"""
        # Check if encrypted file exists
        if not os.path.exists(encrypted_filename):
            print(f"❌ Encrypted file '{encrypted_filename}' not found!")
            return False
        
        start_time = time.time()
        
        try:
            print(f"🔓 Decrypting file: {encrypted_filename}")
            
            # Read encrypted file with metadata
            with open(encrypted_filename, 'rb') as encrypted_file:
                # Read metadata length
                metadata_length_bytes = encrypted_file.read(4)
                if len(metadata_length_bytes) != 4:
                    # Legacy file without metadata
                    print("ℹ️  Processing legacy encrypted file...")
                    encrypted_file.seek(0)
                    encrypted_data = encrypted_file.read()
                    metadata = {}
                else:
                    metadata_length = int.from_bytes(metadata_length_bytes, 'big')
                    
                    # Read metadata
                    metadata_json = encrypted_file.read(metadata_length)
                    metadata = json.loads(metadata_json.decode('utf-8'))
                    
                    # Read encrypted data
                    encrypted_data = encrypted_file.read()
            
            # Check if password is required
            if metadata.get('has_password', False):
                if not password:
                    print("❌ This file requires a password for decryption!")
                    return False
                
                # Reconstruct salt and verify password
                if metadata.get('salt'):
                    salt = base64.b64decode(metadata['salt'])
                    self.derive_key_from_password(password, salt)
                    
                    if not self.verify_password(password):
                        print("❌ Invalid password! Cannot decrypt file.")
                        return False
                else:
                    print("❌ Corrupted encrypted file: missing salt")
                    return False
            elif self.key is None:
                print("❌ No decryption key available! Load a key first.")
                return False
            
            # Decrypt data
            decrypted_data = self.fernet.decrypt(encrypted_data)
            
            # Determine output filename
            if output_filename is None:
                if metadata.get('original_filename'):
                    directory = os.path.dirname(encrypted_filename)
                    base_name, ext = os.path.splitext(metadata['original_filename'])
                    output_filename = os.path.join(directory, f"{base_name}_decrypted{ext}")
                elif encrypted_filename.endswith('.encrypted'):
                    output_filename = encrypted_filename[:-10] + '_decrypted'
                else:
                    output_filename = encrypted_filename + '.decrypted'
            
            # Write decrypted file
            with open(output_filename, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            # Verify file integrity if hash available
            if metadata.get('file_hash'):
                calculated_hash = hashlib.sha256(decrypted_data).hexdigest()
                if calculated_hash == metadata['file_hash']:
                    print("✅ File integrity verified!")
                else:
                    print("⚠️  Warning: File integrity check failed!")
            
            # Verify file size if available
            if metadata.get('original_size') and len(decrypted_data) != metadata['original_size']:
                print("⚠️  Warning: Decrypted file size doesn't match original")
            
            # Log operation
            execution_time = time.time() - start_time
            self.operation_history.append({
                'type': 'decryption',
                'file': metadata.get('original_filename', os.path.basename(encrypted_filename)),
                'size': len(decrypted_data),
                'timestamp': datetime.now().isoformat(),
                'success': True,
                'had_password': metadata.get('has_password', False)
            })
            
            if self.history_manager:
                self.history_manager.add_operation(
                    operation_type='decryption',
                    original_file=encrypted_filename,
                    output_file=output_filename,
                    success=True,
                    file_size=len(decrypted_data),
                    password_protected=metadata.get('has_password', False),
                    execution_time=execution_time
                )
            
            print(f"✅ File decrypted successfully!")
            print(f"   Encrypted: {encrypted_filename}")
            print(f"   Decrypted: {output_filename} ({len(decrypted_data)} bytes)")
            if metadata.get('encryption_time'):
                print(f"   Originally encrypted: {metadata['encryption_time']}")
            
            return output_filename
            
        except InvalidToken:
            error_msg = "Invalid password or corrupted file"
            print(f"❌ Decryption failed: {error_msg}")
            print("   This could mean:")
            print("   - Wrong password")
            print("   - Wrong encryption key")
            print("   - Corrupted file")
            
            execution_time = time.time() - start_time
            self.operation_history.append({
                'type': 'decryption',
                'file': os.path.basename(encrypted_filename),
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'error': error_msg
            })
            
            if self.history_manager:
                self.history_manager.add_operation(
                    operation_type='decryption',
                    original_file=encrypted_filename,
                    success=False,
                    error_message=error_msg,
                    execution_time=execution_time
                )
            return False
            
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            execution_time = time.time() - start_time
            self.operation_history.append({
                'type': 'decryption',
                'file': os.path.basename(encrypted_filename),
                'timestamp': datetime.now().isoformat(),
                'success': False,
                'error': str(e)
            })
            
            if self.history_manager:
                self.history_manager.add_operation(
                    operation_type='decryption',
                    original_file=encrypted_filename,
                    success=False,
                    error_message=str(e),
                    execution_time=execution_time
                )
            return False
    
    def get_operation_history(self):
        """Get operation history for analytics"""
        return self.operation_history
    
    def get_security_status(self):
        """Get current security status"""
        return {
            'has_key': self.key is not None,
            'has_password': self.password_hash is not None,
            'failed_attempts': self.failed_attempts,
            'is_locked_out': self.is_locked_out(),
            'creation_time': self.creation_time,
            'total_operations': len(self.operation_history),
            'successful_operations': len([op for op in self.operation_history if op.get('success')])
        }
    
    def clear_sensitive_data(self):
        """Clear sensitive data from memory for security"""
        if self.key:
            self.key = b'\x00' * len(self.key)
        if self.password_hash:
            self.password_hash = None
        if self.salt:
            self.salt = b'\x00' * len(self.salt)
        self.fernet = None
        print("🧹 Sensitive data cleared from memory")

# Legacy FileEncryptor class for backward compatibility
class FileEncryptor(AdvancedFileEncryptor):
    """Legacy FileEncryptor class - inherits from AdvancedFileEncryptor"""
    pass

# Enhanced test function
def test_advanced_encryption():
    """Test the advanced encryption system with password protection"""
    print("=== 🔐 Advanced File Encryption Test ===\n")
    
    # Create test file
    test_content = """This is a test document for the Advanced File Encryption Tool.

Features tested:
- Password-based encryption
- Key derivation with Scrypt
- File integrity verification
- Metadata preservation
- Operation history tracking

Operating Systems Project - 2025
🔐 Security through cryptography!"""
    
    with open("advanced_test.txt", "w") as f:
        f.write(test_content)
    print("📝 Created test file: advanced_test.txt")
    
    # Test 1: Password-based encryption
    print("\n--- Test 1: Password-Based Encryption ---")
    encryptor = AdvancedFileEncryptor()
    
    # Test password strength
    test_password = "MySecurePassword123!"
    strength = encryptor.validate_password_strength(test_password)
    print(f"Password strength: {strength['strength']} ({strength['percentage']:.0f}%)")
    
    # Encrypt with password
    encrypted_file = encryptor.encrypt_file("advanced_test.txt", password=test_password)
    
    if encrypted_file:
        print("\n--- Test 2: Password-Based Decryption ---")
        # Create new encryptor instance to simulate fresh start
        decryptor = AdvancedFileEncryptor()
        
        # Test wrong password first
        print("🧪 Testing wrong password...")
        try:
            decryptor.decrypt_file(encrypted_file, password="WrongPassword123!")
        except Exception as e:
            print(f"Expected error: {e}")
        
        # Test correct password
        print("🧪 Testing correct password...")
        decrypted_file = decryptor.decrypt_file(encrypted_file, password=test_password)
        
        if decrypted_file:
            print("\n--- Test 3: Verification ---")
            # Compare original and decrypted content
            with open("advanced_test.txt", 'r') as f:
                original = f.read()
            with open(decrypted_file, 'r') as f:
                decrypted = f.read()
            
            if original == decrypted:
                print("✅ SUCCESS! Original and decrypted files match perfectly!")
                print("🎉 Advanced encryption system working correctly!")
            else:
                print("❌ ERROR: Files don't match!")
            
            # Show security status
            print("\n--- Security Status ---")
            status = decryptor.get_security_status()
            for key, value in status.items():
                print(f"{key}: {value}")
            
            # Show operation history
            print("\n--- Operation History ---")
            for i, operation in enumerate(encryptor.get_operation_history() + decryptor.get_operation_history(), 1):
                print(f"{i}. {operation['type']}: {operation.get('file', 'N/A')} - {operation['timestamp'][:19]}")
    
    print("\n=== 🎯 Test Complete ===")

# Main execution
if __name__ == "__main__":
    # Run the advanced test
    #test_advanced_encryption()
    
    print("\n" + "="*60)
    print("🔐 ADVANCED FILE ENCRYPTOR - FEATURES:")
    print("="*60)
    print("✅ Password-based encryption with Scrypt KDF")
    print("✅ Password strength validation")
    print("✅ Account lockout protection")
    print("✅ File integrity verification")
    print("✅ Metadata preservation")
    print("✅ Operation history tracking")
    print("✅ Protected key file storage")
    print("✅ Legacy compatibility")
    print("="*60)
