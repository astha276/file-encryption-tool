import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
from encryption_module import FileEncryptor

class FileEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 File Encryption Tool - OS Project")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Create encryptor instance
        self.encryptor = FileEncryptor()
        
        # Configure style
        self.setup_styles()
        
        # Create GUI elements
        self.create_widgets()
        
        # Update status
        self.update_status()
    
    def setup_styles(self):
        """Configure GUI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure button styles
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
        style.configure('Status.TLabel', font=('Arial', 10), background='#f0f0f0')
        style.configure('Success.TButton', font=('Arial', 10, 'bold'))
        style.configure('Danger.TButton', font=('Arial', 10, 'bold'))
    
    def create_widgets(self):
        """Create all GUI widgets"""
        # Main title
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
        title_frame.pack(fill=tk.X, padx=10, pady=5)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(title_frame, text="🔐 FILE ENCRYPTION TOOL", 
                              font=('Arial', 18, 'bold'), fg='white', bg='#2c3e50')
        title_label.pack(expand=True)
        
        subtitle_label = tk.Label(title_frame, text="Operating Systems Project - Secure File Encryption & Decryption", 
                                 font=('Arial', 10), fg='#ecf0f1', bg='#2c3e50')
        subtitle_label.pack()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs
        self.create_key_management_tab()
        self.create_encryption_tab()
        self.create_decryption_tab()
        self.create_file_manager_tab()
        self.create_status_tab()
        
        # Status bar at bottom
        self.create_status_bar()
    
    def create_key_management_tab(self):
        """Create key management tab"""
        key_frame = ttk.Frame(self.notebook)
        self.notebook.add(key_frame, text="🔑 Key Management")
        
        # Title
        ttk.Label(key_frame, text="Encryption Key Management", style='Header.TLabel').pack(pady=10)
        
        # Generate key section
        gen_frame = tk.LabelFrame(key_frame, text="Generate New Key", font=('Arial', 10, 'bold'), 
                                 bg='#f0f0f0', fg='#2c3e50')
        gen_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(gen_frame, text="Create a new encryption key for securing your files:", 
                 style='Status.TLabel').pack(pady=5)
        
        gen_button_frame = tk.Frame(gen_frame, bg='#f0f0f0')
        gen_button_frame.pack(pady=10)
        
        ttk.Button(gen_button_frame, text="🔑 Generate New Key", 
                  command=self.generate_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(gen_button_frame, text="💾 Save Key As...", 
                  command=self.save_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
        # Load key section
        load_frame = tk.LabelFrame(key_frame, text="Load Existing Key", font=('Arial', 10, 'bold'), 
                                  bg='#f0f0f0', fg='#2c3e50')
        load_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(load_frame, text="Load an existing key file to decrypt files:", 
                 style='Status.TLabel').pack(pady=5)
        
        load_button_frame = tk.Frame(load_frame, bg='#f0f0f0')
        load_button_frame.pack(pady=10)
        
        ttk.Button(load_button_frame, text="📂 Load Key File", 
                  command=self.load_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
        ttk.Button(load_button_frame, text="📋 Quick Load", 
                  command=self.quick_load_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
        # Key status
        self.key_status_frame = tk.LabelFrame(key_frame, text="Current Key Status", 
                                             font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        self.key_status_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.key_status_label = ttk.Label(self.key_status_frame, text="No key loaded", 
                                         style='Status.TLabel')
        self.key_status_label.pack(pady=10)
        
        # Warning
        warning_frame = tk.Frame(key_frame, bg='#fff3cd', relief=tk.RIDGE, bd=2)
        warning_frame.pack(fill=tk.X, padx=20, pady=10)
        
        ttk.Label(warning_frame, text="⚠️ Important: Keep your key files safe! Without the key, encrypted files cannot be recovered.", 
                 font=('Arial', 9, 'bold'), background='#fff3cd', foreground='#856404').pack(pady=5)
    
    def create_encryption_tab(self):
        """Create file encryption tab"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Encrypt Files")
        
        # Title
        ttk.Label(encrypt_frame, text="File Encryption", style='Header.TLabel').pack(pady=10)
        
        # File selection
        select_frame = tk.LabelFrame(encrypt_frame, text="Select File to Encrypt", 
                                    font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        select_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.encrypt_file_var = tk.StringVar()
        self.encrypt_file_entry = ttk.Entry(select_frame, textvariable=self.encrypt_file_var, 
                                           font=('Arial', 10), width=60)
        self.encrypt_file_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
        
        ttk.Button(select_frame, text="📁 Browse", 
                  command=self.browse_encrypt_file).pack(side=tk.RIGHT, padx=5, pady=10)
        
        # Options
        options_frame = tk.LabelFrame(encrypt_frame, text="Encryption Options", 
                                     font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        options_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.delete_original_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="🗑️ Delete original file after encryption (for security)", 
                       variable=self.delete_original_var).pack(anchor=tk.W, padx=10, pady=5)
        
        self.custom_output_var = tk.BooleanVar()
        self.custom_output_check = ttk.Checkbutton(options_frame, text="📝 Use custom output filename:", 
                                                  variable=self.custom_output_var,
                                                  command=self.toggle_custom_output)
        self.custom_output_check.pack(anchor=tk.W, padx=10, pady=2)
        
        self.custom_output_entry = ttk.Entry(options_frame, font=('Arial', 10), width=50, state='disabled')
        self.custom_output_entry.pack(padx=30, pady=2, fill=tk.X)
        
        # Encrypt button
        encrypt_button_frame = tk.Frame(encrypt_frame, bg='#f0f0f0')
        encrypt_button_frame.pack(pady=20)
        
        self.encrypt_button = ttk.Button(encrypt_button_frame, text="🔒 ENCRYPT FILE", 
                                        command=self.encrypt_file, style='Success.TButton')
        self.encrypt_button.pack()
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(encrypt_frame, mode='indeterminate')
        self.encrypt_progress.pack(fill=tk.X, padx=20, pady=5)
    
    def create_decryption_tab(self):
        """Create file decryption tab"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Decrypt Files")
        
        # Title
        ttk.Label(decrypt_frame, text="File Decryption", style='Header.TLabel').pack(pady=10)
        
        # File selection
        select_frame = tk.LabelFrame(decrypt_frame, text="Select Encrypted File", 
                                    font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        select_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.decrypt_file_var = tk.StringVar()
        self.decrypt_file_entry = ttk.Entry(select_frame, textvariable=self.decrypt_file_var, 
                                           font=('Arial', 10), width=60)
        self.decrypt_file_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
        
        ttk.Button(select_frame, text="📁 Browse", 
                  command=self.browse_decrypt_file).pack(side=tk.RIGHT, padx=5, pady=10)
        
        # Quick select encrypted files
        quick_frame = tk.LabelFrame(decrypt_frame, text="Quick Select Encrypted Files", 
                                   font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        quick_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.encrypted_files_listbox = tk.Listbox(quick_frame, height=4, font=('Arial', 9))
        self.encrypted_files_listbox.pack(fill=tk.X, padx=10, pady=5)
        self.encrypted_files_listbox.bind('<Double-1>', self.select_encrypted_file)
        
        ttk.Button(quick_frame, text="🔄 Refresh List", 
                  command=self.refresh_encrypted_files).pack(pady=5)
        
        # Decrypt button
        decrypt_button_frame = tk.Frame(decrypt_frame, bg='#f0f0f0')
        decrypt_button_frame.pack(pady=20)
        
        self.decrypt_button = ttk.Button(decrypt_button_frame, text="🔓 DECRYPT FILE", 
                                        command=self.decrypt_file, style='Danger.TButton')
        self.decrypt_button.pack()
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(decrypt_frame, mode='indeterminate')
        self.decrypt_progress.pack(fill=tk.X, padx=20, pady=5)
    
    def create_file_manager_tab(self):
        """Create file manager tab"""
        files_frame = ttk.Frame(self.notebook)
        self.notebook.add(files_frame, text="📁 File Manager")
        
        # Title
        ttk.Label(files_frame, text="File Manager", style='Header.TLabel').pack(pady=10)
        
        # File list
        list_frame = tk.LabelFrame(files_frame, text="Files in Current Directory", 
                                  font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        # Create treeview for file listing
        columns = ('Name', 'Type', 'Size')
        self.file_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        # Configure columns
        self.file_tree.heading('Name', text='File Name')
        self.file_tree.heading('Type', text='Type')
        self.file_tree.heading('Size', text='Size')
        
        self.file_tree.column('Name', width=400)
        self.file_tree.column('Type', width=150)
        self.file_tree.column('Size', width=100)
        
        # Scrollbar for treeview
        file_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scrollbar.set)
        
        # Pack treeview and scrollbar
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        file_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # Buttons
        button_frame = tk.Frame(files_frame, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="🔄 Refresh", 
                  command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="📂 Open Directory", 
                  command=self.open_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🗑️ Delete Selected", 
                  command=self.delete_selected_file).pack(side=tk.LEFT, padx=5)
    
    def create_status_tab(self):
        """Create status and log tab"""
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="📊 Status & Logs")
        
        # Title
        ttk.Label(status_frame, text="System Status & Activity Log", style='Header.TLabel').pack(pady=10)
        
        # Status information
        status_info_frame = tk.LabelFrame(status_frame, text="Current Status", 
                                         font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        status_info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.status_text = tk.Text(status_info_frame, height=6, font=('Courier', 9), 
                                  bg='#f8f9fa', relief=tk.SUNKEN, bd=1)
        self.status_text.pack(fill=tk.X, padx=10, pady=10)
        
        # Activity log
        log_frame = tk.LabelFrame(status_frame, text="Activity Log", 
                                 font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
        log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, font=('Courier', 9), 
                                                 bg='#ffffff', relief=tk.SUNKEN, bd=1)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Log controls
        log_controls = tk.Frame(log_frame, bg='#f0f0f0')
        log_controls.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(log_controls, text="🗑️ Clear Log", 
                  command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="💾 Save Log", 
                  command=self.save_log).pack(side=tk.LEFT, padx=5)
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        self.status_bar = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, 
                                  bg='#e9ecef', font=('Arial', 9))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def log_message(self, message):
        """Add message to activity log"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Update status bar
        self.status_bar.config(text=message)
    
    def update_status(self):
        """Update status information"""
        # Update key status
        if self.encryptor.key is None:
            self.key_status_label.config(text="❌ No encryption key loaded", foreground='red')
            key_status = "No key loaded"
        else:
            self.key_status_label.config(text="✅ Encryption key loaded and ready", foreground='green')
            key_status = "Key loaded and ready"
        
        # Update status text
        self.status_text.delete(1.0, tk.END)
        status_info = f"""🔑 Key Status: {key_status}
📁 Current Directory: {os.getcwd()}
📊 Files Summary:
   • Total files: {len([f for f in os.listdir('.') if os.path.isfile(f)])}
   • Encrypted files: {len([f for f in os.listdir('.') if f.endswith('.encrypted')])}
   • Key files: {len([f for f in os.listdir('.') if f.endswith('.key')])}
💻 Python Version: {self.get_python_version()}
🔒 Encryption: AES-256 (Fernet)"""
        
        self.status_text.insert(1.0, status_info)
        
        # Refresh file lists
        self.refresh_file_list()
        self.refresh_encrypted_files()
    
    def get_python_version(self):
        """Get Python version"""
        import sys
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
    def generate_key(self):
        """Generate new encryption key"""
        try:
            self.encryptor.generate_key()
            self.log_message("✅ New encryption key generated successfully")
            self.update_status()
            messagebox.showinfo("Success", "New encryption key generated!\n\nRemember to save it using 'Save Key As...' button.")
        except Exception as e:
            self.log_message(f"❌ Key generation failed: {e}")
            messagebox.showerror("Error", f"Failed to generate key:\n{e}")
    
    def save_key(self):
        """Save encryption key to file"""
        if self.encryptor.key is None:
            messagebox.showwarning("Warning", "No key to save! Generate a key first.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Encryption Key",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            if self.encryptor.save_key(filename):
                self.log_message(f"✅ Key saved to: {filename}")
                messagebox.showinfo("Success", f"Key saved successfully to:\n{filename}")
                self.update_status()
            else:
                self.log_message(f"❌ Failed to save key to: {filename}")
                messagebox.showerror("Error", "Failed to save key file!")
    
    def load_key(self):
        """Load encryption key from file"""
        filename = filedialog.askopenfilename(
            title="Load Encryption Key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            if self.encryptor.load_key(filename):
                self.log_message(f"✅ Key loaded from: {filename}")
                messagebox.showinfo("Success", f"Key loaded successfully from:\n{filename}")
                self.update_status()
            else:
                self.log_message(f"❌ Failed to load key from: {filename}")
                messagebox.showerror("Error", "Failed to load key file!")
    
    def quick_load_key(self):
        """Quick load key from available key files"""
        key_files = [f for f in os.listdir('.') if f.endswith('.key')]
        
        if not key_files:
            messagebox.showinfo("Info", "No key files found in current directory.")
            return
        
        # Create selection dialog
        selection_window = tk.Toplevel(self.root)
        selection_window.title("Select Key File")
        selection_window.geometry("400x300")
        selection_window.configure(bg='#f0f0f0')
        
        tk.Label(selection_window, text="Select a key file to load:", 
                font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(pady=10)
        
        key_listbox = tk.Listbox(selection_window, font=('Arial', 10))
        key_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        for key_file in key_files:
            key_listbox.insert(tk.END, key_file)
        
        def load_selected():
            selection = key_listbox.curselection()
            if selection:
                selected_key = key_files[selection[0]]
                if self.encryptor.load_key(selected_key):
                    self.log_message(f"✅ Key loaded from: {selected_key}")
                    messagebox.showinfo("Success", f"Key loaded from: {selected_key}")
                    self.update_status()
                    selection_window.destroy()
                else:
                    messagebox.showerror("Error", "Failed to load selected key!")
        
        button_frame = tk.Frame(selection_window, bg='#f0f0f0')
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Load Selected", command=load_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=selection_window.destroy).pack(side=tk.LEFT, padx=5)
    
    def browse_encrypt_file(self):
        """Browse for file to encrypt"""
        filename = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All files", "*.*")]
        )
        
        if filename:
            self.encrypt_file_var.set(filename)
    
    def toggle_custom_output(self):
        """Toggle custom output filename entry"""
        if self.custom_output_var.get():
            self.custom_output_entry.config(state='normal')
        else:
            self.custom_output_entry.config(state='disabled')
    
    def encrypt_file(self):
        """Encrypt selected file"""
        if self.encryptor.key is None:
            messagebox.showwarning("Warning", "No encryption key loaded!\n\nPlease generate or load a key first.")
            return
        
        input_file = self.encrypt_file_var.get().strip()
        if not input_file:
            messagebox.showwarning("Warning", "Please select a file to encrypt!")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found:\n{input_file}")
            return
        
        # Determine output filename
        output_file = None
        if self.custom_output_var.get():
            output_file = self.custom_output_entry.get().strip()
            if not output_file:
                messagebox.showwarning("Warning", "Please enter a custom output filename!")
                return
        
        try:
            # Show progress
            self.encrypt_progress.start()
            self.encrypt_button.config(state='disabled')
            self.root.update()
            
            # Encrypt file
            result = self.encryptor.encrypt_file(input_file, output_file)
            
            if result:
                self.log_message(f"✅ File encrypted: {input_file} -> {result}")
                
                # Delete original if requested
                if self.delete_original_var.get():
                    try:
                        os.remove(input_file)
                        self.log_message(f"🗑️ Original file deleted: {input_file}")
                    except Exception as e:
                        self.log_message(f"⚠️ Could not delete original file: {e}")
                
                messagebox.showinfo("Success", f"File encrypted successfully!\n\nEncrypted file: {result}")
                self.update_status()
                
                # Clear form
                self.encrypt_file_var.set("")
                self.custom_output_entry.delete(0, tk.END)
                self.delete_original_var.set(False)
                self.custom_output_var.set(False)
                self.toggle_custom_output()
            else:
                self.log_message(f"❌ Encryption failed for: {input_file}")
                messagebox.showerror("Error", "Encryption failed!")
        
        except Exception as e:
            self.log_message(f"❌ Encryption error: {e}")
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
        
        finally:
            # Hide progress
            self.encrypt_progress.stop()
            self.encrypt_button.config(state='normal')
    
    def browse_decrypt_file(self):
        """Browse for file to decrypt"""
        filename = filedialog.askopenfilename(
            title="Select Encrypted File to Decrypt",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        
        if filename:
            self.decrypt_file_var.set(filename)
    
    def refresh_encrypted_files(self):
        """Refresh list of encrypted files"""
        self.encrypted_files_listbox.delete(0, tk.END)
        
        encrypted_files = [f for f in os.listdir('.') if f.endswith('.encrypted')]
        
        if encrypted_files:
            for file in encrypted_files:
                self.encrypted_files_listbox.insert(tk.END, file)
        else:
            self.encrypted_files_listbox.insert(tk.END, "No encrypted files found")
    
    def select_encrypted_file(self, event):
        """Select encrypted file from list"""
        selection = self.encrypted_files_listbox.curselection()
        if selection:
            selected_file = self.encrypted_files_listbox.get(selection[0])
            if selected_file != "No encrypted files found":
                self.decrypt_file_var.set(selected_file)
    
    def decrypt_file(self):
        """Decrypt selected file"""
        if self.encryptor.key is None:
            messagebox.showwarning("Warning", "No decryption key loaded!\n\nPlease load the correct encryption key first.")
            return
        
        input_file = self.decrypt_file_var.get().strip()
        if not input_file:
            messagebox.showwarning("Warning", "Please select an encrypted file to decrypt!")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found:\n{input_file}")
            return
        
        try:
            # Show progress
            self.decrypt_progress.start()
            self.decrypt_button.config(state='disabled')
            self.root.update()
            
            # Decrypt file
            result = self.encryptor.decrypt_file(input_file)
            
            if result:
                self.log_message(f"✅ File decrypted: {input_file} -> {result}")
                messagebox.showinfo("Success", f"File decrypted successfully!\n\nDecrypted file: {result}")
                self.update_status()
                
                # Clear form
                self.decrypt_file_var.set("")
            else:
                self.log_message(f"❌ Decryption failed for: {input_file}")
                messagebox.showerror("Error", "Decryption failed!\n\nThis could mean:\n• Wrong encryption key\n• Corrupted file\n• File wasn't encrypted with this tool")
        
        except Exception as e:
            self.log_message(f"❌ Decryption error: {e}")
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
        
        finally:
            # Hide progress
            self.decrypt_progress.stop()
            self.decrypt_button.config(state='normal')
    
    def refresh_file_list(self):
        """Refresh file list in file manager"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        # Get files
        try:
            files = os.listdir('.')
            
            for file in files:
                if os.path.isfile(file):
                    # Determine file type
                    if file.endswith('.encrypted'):
                        file_type = "🔒 Encrypted File"
                    elif file.endswith('.key'):
                        file_type = "🔑 Key File"
                    elif file.endswith('.py'):
                        file_type = "🐍 Python File"
                    elif file.endswith('.txt'):
                        file_type = "📄 Text File"
                    else:
                        file_type = "📁 File"
                    
                    # Get file size
                    size = os.path.getsize(file)
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f} KB"
                    else:
                        size_str = f"{size / (1024 * 1024):.1f} MB"
                    
                    # Insert into tree
                    self.file_tree.insert('', tk.END, values=(file, file_type, size_str))
        
        except Exception as e:
            self.log_message(f"❌ Error refreshing file list: {e}")
    
    def open_directory(self):
        """Open current directory in file explorer"""
        import subprocess
        import platform
        
        try:
            if platform.system() == "Windows":
                subprocess.run(["explorer", "."])
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", "."])
            else:  # Linux
                subprocess.run(["xdg-open", "."])
            
            self.log_message("📂 Directory opened in file explorer")
        except Exception as e:
            self.log_message(f"❌ Error opening directory: {e}")
            messagebox.showerror("Error", f"Could not open directory:\n{e}")
    
    def delete_selected_file(self):
        """Delete selected file"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to delete!")
            return
        
        # Get selected file name
        item = self.file_tree.item(selection[0])
        filename = item['values'][0]
        
        # Confirm deletion
        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete:\n{filename}\n\nThis action cannot be undone!"):
            try:
                os.remove(filename)
                self.log_message(f"🗑️ File deleted: {filename}")
                self.refresh_file_list()
                self.update_status()
                messagebox.showinfo("Success", f"File deleted successfully:\n{filename}")
            except Exception as e:
                self.log_message(f"❌ Error deleting file: {e}")
                messagebox.showerror("Error", f"Could not delete file:\n{e}")
    
    def clear_log(self):
        """Clear activity log"""
        self.log_text.delete(1.0, tk.END)
        self.log_message("🗑️ Activity log cleared")
    
    def save_log(self):
        """Save activity log to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Activity Log",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.log_text.get(1.0, tk.END))
                
                self.log_message(f"💾 Log saved to: {filename}")
                messagebox.showinfo("Success", f"Log saved successfully to:\n{filename}")
            except Exception as e:
                self.log_message(f"❌ Error saving log: {e}")
                messagebox.showerror("Error", f"Could not save log:\n{e}")

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = FileEncryptionGUI(root)
    
    # Log startup
    app.log_message("🚀 File Encryption Tool started")
    app.log_message("📋 GUI interface loaded successfully")
    
    # Center window on screen
    root.eval('tk::PlaceWindow . center')
    
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    main()
