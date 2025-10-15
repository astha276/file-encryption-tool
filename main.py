# Import our encryption module
from encryption_module import FileEncryptor
import os
import sys

def clear_screen():
    """Clear the console screen"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_header():
    """Display the program header"""
    print("=" * 60)
    print("🔐 FILE ENCRYPTION TOOL - OPERATING SYSTEMS PROJECT")
    print("=" * 60)
    print("   Secure File Encryption & Decryption System")
    print("   Built with Python & AES-256 Encryption")
    print("=" * 60)

def display_menu():
    """Display the main menu options"""
    print("\n📋 MAIN MENU:")
    print("-" * 30)
    print("1. 🔑 Generate New Encryption Key")
    print("2. 📂 Load Existing Key File")
    print("3. 🔒 Encrypt a File")
    print("4. 🔓 Decrypt a File")
    print("5. 📊 View Current Status")
    print("6. 🗂️  List Files in Directory")
    print("7. ❓ Help & Instructions")
    print("8. 🚪 Exit Program")
    print("-" * 30)

def get_user_choice():
    """Get and validate user menu choice"""
    while True:
        try:
            choice = input("\n👉 Enter your choice (1-8): ").strip()
            if choice in ['1', '2', '3', '4', '5', '6', '7', '8']:
                return choice
            else:
                print("❌ Invalid choice! Please enter a number between 1-8.")
        except KeyboardInterrupt:
            print("\n\n👋 Program interrupted by user. Goodbye!")
            sys.exit()

def generate_key_menu(encryptor):
    """Handle key generation"""
    print("\n" + "="*50)
    print("🔑 GENERATE NEW ENCRYPTION KEY")
    print("="*50)
    
    # Generate the key
    encryptor.generate_key()
    
    # Ask where to save it
    while True:
        key_filename = input("\n📝 Enter filename to save key (e.g., 'my_key.key'): ").strip()
        
        if not key_filename:
            print("❌ Please enter a filename!")
            continue
        
        # Add .key extension if not present
        if not key_filename.endswith('.key'):
            key_filename += '.key'
        
        # Check if file already exists
        if os.path.exists(key_filename):
            overwrite = input(f"⚠️  File '{key_filename}' already exists. Overwrite? (y/n): ").strip().lower()
            if overwrite != 'y':
                continue
        
        # Save the key
        if encryptor.save_key(key_filename):
            print(f"\n✅ SUCCESS! Key saved as: {key_filename}")
            print("⚠️  IMPORTANT: Keep this key file safe! You need it to decrypt files.")
            break
        else:
            print("❌ Failed to save key. Please try again.")

def load_key_menu(encryptor):
    """Handle key loading"""
    print("\n" + "="*50)
    print("📂 LOAD EXISTING ENCRYPTION KEY")
    print("="*50)
    
    # Show available key files
    key_files = [f for f in os.listdir('.') if f.endswith('.key')]
    
    if key_files:
        print("\n📋 Available key files:")
        for i, key_file in enumerate(key_files, 1):
            print(f"   {i}. {key_file}")
    else:
        print("\n⚠️  No .key files found in current directory.")
    
    while True:
        key_filename = input("\n📝 Enter key filename: ").strip()
        
        if not key_filename:
            print("❌ Please enter a filename!")
            continue
        
        if encryptor.load_key(key_filename):
            print(f"\n✅ SUCCESS! Key loaded from: {key_filename}")
            break
        else:
            retry = input("\n🔄 Try again? (y/n): ").strip().lower()
            if retry != 'y':
                break

def encrypt_file_menu(encryptor):
    """Handle file encryption"""
    print("\n" + "="*50)
    print("🔒 ENCRYPT A FILE")
    print("="*50)
    
    # Check if key is loaded
    if encryptor.key is None:
        print("❌ No encryption key loaded!")
        print("   Please generate a new key or load an existing one first.")
        return
    
    # Show available files
    files = [f for f in os.listdir('.') if os.path.isfile(f) and not f.endswith('.encrypted') and not f.endswith('.key')]
    
    if files:
        print("\n📋 Available files to encrypt:")
        for i, file in enumerate(files, 1):
            print(f"   {i}. {file}")
    else:
        print("\n⚠️  No suitable files found for encryption.")
    
    while True:
        filename = input("\n📝 Enter filename to encrypt: ").strip()
        
        if not filename:
            print("❌ Please enter a filename!")
            continue
        
        if not os.path.exists(filename):
            print(f"❌ File '{filename}' not found!")
            retry = input("🔄 Try again? (y/n): ").strip().lower()
            if retry != 'y':
                break
            continue
        
        # Ask for output filename
        output_filename = input(f"📝 Output filename (press Enter for '{filename}.encrypted'): ").strip()
        if not output_filename:
            output_filename = None
        
        # Encrypt the file
        result = encryptor.encrypt_file(filename, output_filename)
        if result:
            print(f"\n🎉 SUCCESS! File encrypted successfully!")
            
            # Ask if user wants to delete original
            delete_original = input("\n🗑️  Delete original file for security? (y/n): ").strip().lower()
            if delete_original == 'y':
                try:
                    os.remove(filename)
                    print(f"✅ Original file '{filename}' deleted.")
                except Exception as e:
                    print(f"❌ Could not delete original file: {e}")
        break

def decrypt_file_menu(encryptor):
    """Handle file decryption"""
    print("\n" + "="*50)
    print("🔓 DECRYPT A FILE")
    print("="*50)
    
    # Check if key is loaded
    if encryptor.key is None:
        print("❌ No decryption key loaded!")
        print("   Please load the correct encryption key first.")
        return
    
    # Show available encrypted files
    encrypted_files = [f for f in os.listdir('.') if f.endswith('.encrypted')]
    
    if encrypted_files:
        print("\n📋 Available encrypted files:")
        for i, file in enumerate(encrypted_files, 1):
            print(f"   {i}. {file}")
    else:
        print("\n⚠️  No encrypted files found.")
    
    while True:
        filename = input("\n📝 Enter encrypted filename to decrypt: ").strip()
        
        if not filename:
            print("❌ Please enter a filename!")
            continue
        
        if not os.path.exists(filename):
            print(f"❌ File '{filename}' not found!")
            retry = input("🔄 Try again? (y/n): ").strip().lower()
            if retry != 'y':
                break
            continue
        
        # Ask for output filename
        suggested_name = filename.replace('.encrypted', '') if filename.endswith('.encrypted') else filename + '.decrypted'
        output_filename = input(f"📝 Output filename (press Enter for '{suggested_name}'): ").strip()
        if not output_filename:
            output_filename = None
        
        # Decrypt the file
        result = encryptor.decrypt_file(filename, output_filename)
        if result:
            print(f"\n🎉 SUCCESS! File decrypted successfully!")
        break

def show_status(encryptor):
    """Show current program status"""
    print("\n" + "="*50)
    print("📊 CURRENT STATUS")
    print("="*50)
    
    # Key status
    if encryptor.key is None:
        print("🔑 Key Status: ❌ No key loaded")
    else:
        print("🔑 Key Status: ✅ Key loaded and ready")
    
    # File counts
    all_files = os.listdir('.')
    regular_files = [f for f in all_files if os.path.isfile(f) and not f.endswith('.encrypted') and not f.endswith('.key')]
    encrypted_files = [f for f in all_files if f.endswith('.encrypted')]
    key_files = [f for f in all_files if f.endswith('.key')]
    
    print(f"📁 Files in directory: {len(all_files)}")
    print(f"📄 Regular files: {len(regular_files)}")
    print(f"🔒 Encrypted files: {len(encrypted_files)}")
    print(f"🔑 Key files: {len(key_files)}")

def list_files():
    """List all files in current directory"""
    print("\n" + "="*50)
    print("🗂️  FILES IN CURRENT DIRECTORY")
    print("="*50)
    
    files = os.listdir('.')
    
    if not files:
        print("📂 Directory is empty.")
        return
    
    # Categorize files
    regular_files = []
    encrypted_files = []
    key_files = []
    other_files = []
    
    for file in files:
        if os.path.isfile(file):
            if file.endswith('.encrypted'):
                encrypted_files.append(file)
            elif file.endswith('.key'):
                key_files.append(file)
            elif file.endswith('.py'):
                other_files.append(file)
            else:
                regular_files.append(file)
    
    if regular_files:
        print("\n📄 Regular Files:")
        for file in regular_files:
            size = os.path.getsize(file)
            print(f"   • {file} ({size} bytes)")
    
    if encrypted_files:
        print("\n🔒 Encrypted Files:")
        for file in encrypted_files:
            size = os.path.getsize(file)
            print(f"   • {file} ({size} bytes)")
    
    if key_files:
        print("\n🔑 Key Files:")
        for file in key_files:
            print(f"   • {file}")
    
    if other_files:
        print("\n💻 Program Files:")
        for file in other_files:
            print(f"   • {file}")

def show_help():
    """Display help and instructions"""
    print("\n" + "="*50)
    print("❓ HELP & INSTRUCTIONS")
    print("="*50)
    
    print("""
📚 HOW TO USE THIS TOOL:

1️⃣  FIRST TIME SETUP:
   • Choose option 1 to generate a new encryption key
   • Save the key with a memorable name (e.g., 'my_secret_key.key')
   • Keep this key file safe - you need it to decrypt files!

2️⃣  TO ENCRYPT A FILE:
   • Make sure you have a key loaded (option 1 or 2)
   • Choose option 3 to encrypt a file
   • Select the file you want to encrypt
   • The encrypted file will be created with '.encrypted' extension

3️⃣  TO DECRYPT A FILE:
   • Load the same key that was used for encryption (option 2)
   • Choose option 4 to decrypt a file
   • Select the encrypted file
   • The original file will be restored

⚠️  IMPORTANT SECURITY NOTES:
   • Never lose your key file - encrypted files cannot be recovered without it!
   • Keep key files in a secure location
   • Consider deleting original files after encryption for security
   • Use strong, unique key files for different sets of files

🔒 WHAT FILES CAN BE ENCRYPTED:
   • Text files (.txt, .doc, etc.)
   • Images (.jpg, .png, .gif, etc.)
   • Videos (.mp4, .avi, etc.)
   • Any file type can be encrypted!

💡 TIPS:
   • Use option 5 to check your current status
   • Use option 6 to see all files in the directory
   • The tool creates backups - original files are kept unless you choose to delete them
""")
def format_file_size(size_bytes):
    """Convert bytes to human readable format"""
    if size_bytes < 1024:
        return f"{size_bytes} bytes"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"

def main():
    """Main program function"""
    # Create encryptor instance
    encryptor = FileEncryptor()
    
    # Main program loop
    while True:
        clear_screen()
        display_header()
        display_menu()
        
        choice = get_user_choice()
        
        if choice == '1':
            generate_key_menu(encryptor)
        elif choice == '2':
            load_key_menu(encryptor)
        elif choice == '3':
            encrypt_file_menu(encryptor)
        elif choice == '4':
            decrypt_file_menu(encryptor)
        elif choice == '5':
            show_status(encryptor)
        elif choice == '6':
            list_files()
        elif choice == '7':
            show_help()
        elif choice == '8':
            print("\n" + "="*50)
            print("👋 THANK YOU FOR USING FILE ENCRYPTION TOOL!")
            print("="*50)
            print("🎓 Operating Systems Project - File Encryption")
            print("💻 Built with Python & Cryptography")
            print("🔒 Stay secure!")
            print("="*50)
            sys.exit()
        
        # Wait for user to continue
        input("\n⏸️  Press Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n👋 Program interrupted. Goodbye!")
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        print("Please report this issue if it persists.")
