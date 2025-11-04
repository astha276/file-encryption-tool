#!/usr/bin/env python3
"""
Advanced File Encryption Tool - Console Interface
Operating Systems Project - Password Protected Edition
"""

import os
import getpass
from encryption_module import AdvancedFileEncryptor

def main():
    print("="*60)
    print("🔐 ADVANCED FILE ENCRYPTION TOOL - CONSOLE")
    print("="*60)
    print("Password-Protected • AES-256 • Operating Systems Project")
    print()
    
    encryptor = AdvancedFileEncryptor()
    
    while True:
        print("\n📋 MAIN MENU:")
        print("1. 🔐 Set Master Password")
        print("2. 🔒 Encrypt File")
        print("3. 🔓 Decrypt File")
        print("4. 📦 Batch Encrypt Files")
        print("5. 📊 View Statistics")
        print("6. 📚 View History")
        print("7. 🧹 Clear Sensitive Data")
        print("8. ❌ Exit")
        
        choice = input("\nEnter your choice (1-8): ").strip()
        
        if choice == '1':
            set_master_password(encryptor)
        elif choice == '2':
            encrypt_file(encryptor)
        elif choice == '3':
            decrypt_file(encryptor)
        elif choice == '4':
            batch_encrypt(encryptor)
        elif choice == '5':
            show_statistics(encryptor)
        elif choice == '6':
            show_history(encryptor)
        elif choice == '7':
            encryptor.clear_sensitive_data()
            print("✅ Sensitive data cleared from memory")
        elif choice == '8':
            print("\n🔐 Thank you for using Advanced File Encryption Tool!")
            print("Stay secure! 🛡️")
            break
        else:
            print("❌ Invalid choice. Please try again.")

def set_master_password(encryptor):
    print("\n🔐 SET MASTER PASSWORD")
    print("-" * 30)
    
    password = getpass.getpass("Enter master password: ")
    if not password:
        print("❌ Password cannot be empty!")
        return
    
    # Check password strength
    strength = encryptor.validate_password_strength(password)
    print(f"Password strength: {strength['strength']} ({strength['percentage']:.0f}%)")
    
    if strength['score'] < 2:
        print(f"⚠️ Warning: {', '.join(strength['feedback'])}")
        if input("Continue with weak password? (y/N): ").lower() != 'y':
            return
    
    try:
        encryptor.derive_key_from_password(password)
        print("✅ Master password set successfully!")
    except Exception as e:
        print(f"❌ Error: {e}")

def encrypt_file(encryptor):
    print("\n🔒 ENCRYPT FILE")
    print("-" * 20)
    
    file_path = input("Enter file path to encrypt: ").strip().strip('"')
    
    if not os.path.exists(file_path):
        print("❌ File not found!")
        return
    
    if not encryptor.key and not encryptor.password_hash:
        print("❌ No master password set! Please set password first.")
        return
    
    password = getpass.getpass("Enter password for encryption: ")
    
    try:
        result = encryptor.encrypt_file(file_path, password)
        if result:
            print(f"✅ File encrypted successfully!")
            print(f"📁 Encrypted file: {result}")
        else:
            print("❌ Encryption failed!")
    except Exception as e:
        print(f"❌ Error: {e}")

def decrypt_file(encryptor):
    print("\n🔓 DECRYPT FILE")
    print("-" * 20)
    
    file_path = input("Enter encrypted file path: ").strip().strip('"')
    
    if not os.path.exists(file_path):
        print("❌ File not found!")
        return
    
    password = getpass.getpass("Enter password for decryption: ")
    
    try:
        result = encryptor.decrypt_file(file_path, password)
        if result:
            print(f"✅ File decrypted successfully!")
            print(f"📁 Decrypted file: {result}")
        else:
            print("❌ Decryption failed!")
    except Exception as e:
        print(f"❌ Error: {e}")

def batch_encrypt(encryptor):
    print("\n📦 BATCH ENCRYPT FILES")
    print("-" * 25)
    
    files = []
    print("Enter file paths (press Enter twice to finish):")
    
    while True:
        file_path = input("File path: ").strip().strip('"')
        if not file_path:
            break
        if os.path.exists(file_path):
            files.append(file_path)
            print(f"✅ Added: {os.path.basename(file_path)}")
        else:
            print(f"❌ File not found: {file_path}")
    
    if not files:
        print("❌ No valid files selected!")
        return
    
    password = getpass.getpass("Enter password for batch encryption: ")
    
    print(f"\n🚀 Processing {len(files)} files...")
    successful = 0
    
    for i, file_path in enumerate(files, 1):
        print(f"Processing {i}/{len(files)}: {os.path.basename(file_path)}")
        try:
            result = encryptor.encrypt_file(file_path, password)
            if result:
                successful += 1
                print(f"  ✅ Success")
            else:
                print(f"  ❌ Failed")
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n📊 Batch complete: {successful}/{len(files)} files encrypted successfully")

def show_statistics(encryptor):
    print("\n📊 STATISTICS")
    print("-" * 15)
    
    try:
        stats = encryptor.history_manager.get_statistics()
        status = encryptor.get_security_status()
        
        print(f"Total Operations: {stats['total_operations']}")
        print(f"Successful Operations: {stats['successful_operations']}")
        print(f"Failed Operations: {stats['failed_operations']}")
        print(f"Success Rate: {stats['success_rate']:.1f}%")
        print(f"Files Encrypted: {stats['total_encryptions']}")
        print(f"Files Decrypted: {stats['total_decryptions']}")
        print(f"Data Processed: {stats['total_processed_size'] / 1024 / 1024:.1f} MB")
        print(f"Batch Operations: {stats['total_batches']}")
        
        print(f"\n🔐 Security Status:")
        print(f"Key Loaded: {'Yes' if status['has_key'] else 'No'}")
        print(f"Password Protected: {'Yes' if status['has_password'] else 'No'}")
        print(f"Failed Attempts: {status['failed_attempts']}")
        
    except Exception as e:
        print(f"❌ Error loading statistics: {e}")

def show_history(encryptor):
    print("\n📚 OPERATION HISTORY")
    print("-" * 25)
    
    try:
        history = encryptor.history_manager.get_history(limit=20)
        
        if not history:
            print("No operations found.")
            return
        
        print(f"{'Time':<20} {'Operation':<12} {'File':<30} {'Status':<10}")
        print("-" * 75)
        
        for op in history:
            timestamp = op['timestamp'][:19]
            operation = op['operation_type'].title()
            filename = os.path.basename(op['original_file'])[:28]
            status = 'Success' if op['success'] else 'Failed'
            
            print(f"{timestamp:<20} {operation:<12} {filename:<30} {status:<10}")
            
    except Exception as e:
        print(f"❌ Error loading history: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n🔐 Encryption tool terminated by user. Stay secure! 🛡️")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
