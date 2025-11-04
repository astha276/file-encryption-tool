# import tkinter as tk
# from tkinter import ttk, filedialog, messagebox, scrolledtext
# import os
# from encryption_module import FileEncryptor

# class FileEncryptionGUI:
#     def __init__(self, root):
#         self.root = root
#         self.root.title("🔐 File Encryption Tool - OS Project")
#         self.root.geometry("800x600")
#         self.root.configure(bg='#f0f0f0')
        
#         # Create encryptor instance
#         self.encryptor = FileEncryptor()
        
#         # Configure style
#         self.setup_styles()
        
#         # Create GUI elements
#         self.create_widgets()
        
#         # Update status
#         self.update_status()
    
#     def setup_styles(self):
#         """Configure GUI styles"""
#         style = ttk.Style()
#         style.theme_use('clam')
        
#         # Configure button styles
#         style.configure('Title.TLabel', font=('Arial', 16, 'bold'), background='#f0f0f0')
#         style.configure('Header.TLabel', font=('Arial', 12, 'bold'), background='#f0f0f0')
#         style.configure('Status.TLabel', font=('Arial', 10), background='#f0f0f0')
#         style.configure('Success.TButton', font=('Arial', 10, 'bold'))
#         style.configure('Danger.TButton', font=('Arial', 10, 'bold'))
    
#     def create_widgets(self):
#         """Create all GUI widgets"""
#         # Main title
#         title_frame = tk.Frame(self.root, bg='#2c3e50', height=80)
#         title_frame.pack(fill=tk.X, padx=10, pady=5)
#         title_frame.pack_propagate(False)
        
#         title_label = tk.Label(title_frame, text="🔐 FILE ENCRYPTION TOOL", 
#                               font=('Arial', 18, 'bold'), fg='white', bg='#2c3e50')
#         title_label.pack(expand=True)
        
#         subtitle_label = tk.Label(title_frame, text="Operating Systems Project - Secure File Encryption & Decryption", 
#                                  font=('Arial', 10), fg='#ecf0f1', bg='#2c3e50')
#         subtitle_label.pack()
        
#         # Create notebook for tabs
#         self.notebook = ttk.Notebook(self.root)
#         self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
#         # Create tabs
#         self.create_key_management_tab()
#         self.create_encryption_tab()
#         self.create_decryption_tab()
#         self.create_file_manager_tab()
#         self.create_status_tab()
        
#         # Status bar at bottom
#         self.create_status_bar()
    
#     def create_key_management_tab(self):
#         """Create key management tab"""
#         key_frame = ttk.Frame(self.notebook)
#         self.notebook.add(key_frame, text="🔑 Key Management")
        
#         # Title
#         ttk.Label(key_frame, text="Encryption Key Management", style='Header.TLabel').pack(pady=10)
        
#         # Generate key section
#         gen_frame = tk.LabelFrame(key_frame, text="Generate New Key", font=('Arial', 10, 'bold'), 
#                                  bg='#f0f0f0', fg='#2c3e50')
#         gen_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         ttk.Label(gen_frame, text="Create a new encryption key for securing your files:", 
#                  style='Status.TLabel').pack(pady=5)
        
#         gen_button_frame = tk.Frame(gen_frame, bg='#f0f0f0')
#         gen_button_frame.pack(pady=10)
        
#         ttk.Button(gen_button_frame, text="🔑 Generate New Key", 
#                   command=self.generate_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
#         ttk.Button(gen_button_frame, text="💾 Save Key As...", 
#                   command=self.save_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
#         # Load key section
#         load_frame = tk.LabelFrame(key_frame, text="Load Existing Key", font=('Arial', 10, 'bold'), 
#                                   bg='#f0f0f0', fg='#2c3e50')
#         load_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         ttk.Label(load_frame, text="Load an existing key file to decrypt files:", 
#                  style='Status.TLabel').pack(pady=5)
        
#         load_button_frame = tk.Frame(load_frame, bg='#f0f0f0')
#         load_button_frame.pack(pady=10)
        
#         ttk.Button(load_button_frame, text="📂 Load Key File", 
#                   command=self.load_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
#         ttk.Button(load_button_frame, text="📋 Quick Load", 
#                   command=self.quick_load_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        
#         # Key status
#         self.key_status_frame = tk.LabelFrame(key_frame, text="Current Key Status", 
#                                              font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         self.key_status_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.key_status_label = ttk.Label(self.key_status_frame, text="No key loaded", 
#                                          style='Status.TLabel')
#         self.key_status_label.pack(pady=10)
        
#         # Warning
#         warning_frame = tk.Frame(key_frame, bg='#fff3cd', relief=tk.RIDGE, bd=2)
#         warning_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         ttk.Label(warning_frame, text="⚠️ Important: Keep your key files safe! Without the key, encrypted files cannot be recovered.", 
#                  font=('Arial', 9, 'bold'), background='#fff3cd', foreground='#856404').pack(pady=5)
    
#     def create_encryption_tab(self):
#         """Create file encryption tab"""
#         encrypt_frame = ttk.Frame(self.notebook)
#         self.notebook.add(encrypt_frame, text="🔒 Encrypt Files")
        
#         # Title
#         ttk.Label(encrypt_frame, text="File Encryption", style='Header.TLabel').pack(pady=10)
        
#         # File selection
#         select_frame = tk.LabelFrame(encrypt_frame, text="Select File to Encrypt", 
#                                     font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         select_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.encrypt_file_var = tk.StringVar()
#         self.encrypt_file_entry = ttk.Entry(select_frame, textvariable=self.encrypt_file_var, 
#                                            font=('Arial', 10), width=60)
#         self.encrypt_file_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
        
#         ttk.Button(select_frame, text="📁 Browse", 
#                   command=self.browse_encrypt_file).pack(side=tk.RIGHT, padx=5, pady=10)
        
#         # Options
#         options_frame = tk.LabelFrame(encrypt_frame, text="Encryption Options", 
#                                      font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         options_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.delete_original_var = tk.BooleanVar()
#         ttk.Checkbutton(options_frame, text="🗑️ Delete original file after encryption (for security)", 
#                        variable=self.delete_original_var).pack(anchor=tk.W, padx=10, pady=5)
        
#         self.custom_output_var = tk.BooleanVar()
#         self.custom_output_check = ttk.Checkbutton(options_frame, text="📝 Use custom output filename:", 
#                                                   variable=self.custom_output_var,
#                                                   command=self.toggle_custom_output)
#         self.custom_output_check.pack(anchor=tk.W, padx=10, pady=2)
        
#         self.custom_output_entry = ttk.Entry(options_frame, font=('Arial', 10), width=50, state='disabled')
#         self.custom_output_entry.pack(padx=30, pady=2, fill=tk.X)
        
#         # Encrypt button
#         encrypt_button_frame = tk.Frame(encrypt_frame, bg='#f0f0f0')
#         encrypt_button_frame.pack(pady=20)
        
#         self.encrypt_button = ttk.Button(encrypt_button_frame, text="🔒 ENCRYPT FILE", 
#                                         command=self.encrypt_file, style='Success.TButton')
#         self.encrypt_button.pack()
        
#         # Progress bar
#         self.encrypt_progress = ttk.Progressbar(encrypt_frame, mode='indeterminate')
#         self.encrypt_progress.pack(fill=tk.X, padx=20, pady=5)
    
#     def create_decryption_tab(self):
#         """Create file decryption tab"""
#         decrypt_frame = ttk.Frame(self.notebook)
#         self.notebook.add(decrypt_frame, text="🔓 Decrypt Files")
        
#         # Title
#         ttk.Label(decrypt_frame, text="File Decryption", style='Header.TLabel').pack(pady=10)
        
#         # File selection
#         select_frame = tk.LabelFrame(decrypt_frame, text="Select Encrypted File", 
#                                     font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         select_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.decrypt_file_var = tk.StringVar()
#         self.decrypt_file_entry = ttk.Entry(select_frame, textvariable=self.decrypt_file_var, 
#                                            font=('Arial', 10), width=60)
#         self.decrypt_file_entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
        
#         ttk.Button(select_frame, text="📁 Browse", 
#                   command=self.browse_decrypt_file).pack(side=tk.RIGHT, padx=5, pady=10)
        
#         # Quick select encrypted files
#         quick_frame = tk.LabelFrame(decrypt_frame, text="Quick Select Encrypted Files", 
#                                    font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         quick_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.encrypted_files_listbox = tk.Listbox(quick_frame, height=4, font=('Arial', 9))
#         self.encrypted_files_listbox.pack(fill=tk.X, padx=10, pady=5)
#         self.encrypted_files_listbox.bind('<Double-1>', self.select_encrypted_file)
        
#         ttk.Button(quick_frame, text="🔄 Refresh List", 
#                   command=self.refresh_encrypted_files).pack(pady=5)
        
#         # Decrypt button
#         decrypt_button_frame = tk.Frame(decrypt_frame, bg='#f0f0f0')
#         decrypt_button_frame.pack(pady=20)
        
#         self.decrypt_button = ttk.Button(decrypt_button_frame, text="🔓 DECRYPT FILE", 
#                                         command=self.decrypt_file, style='Danger.TButton')
#         self.decrypt_button.pack()
        
#         # Progress bar
#         self.decrypt_progress = ttk.Progressbar(decrypt_frame, mode='indeterminate')
#         self.decrypt_progress.pack(fill=tk.X, padx=20, pady=5)
    
#     def create_file_manager_tab(self):
#         """Create file manager tab"""
#         files_frame = ttk.Frame(self.notebook)
#         self.notebook.add(files_frame, text="📁 File Manager")
        
#         # Title
#         ttk.Label(files_frame, text="File Manager", style='Header.TLabel').pack(pady=10)
        
#         # File list
#         list_frame = tk.LabelFrame(files_frame, text="Files in Current Directory", 
#                                   font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         list_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
#         # Create treeview for file listing
#         columns = ('Name', 'Type', 'Size')
#         self.file_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
#         # Configure columns
#         self.file_tree.heading('Name', text='File Name')
#         self.file_tree.heading('Type', text='Type')
#         self.file_tree.heading('Size', text='Size')
        
#         self.file_tree.column('Name', width=400)
#         self.file_tree.column('Type', width=150)
#         self.file_tree.column('Size', width=100)
        
#         # Scrollbar for treeview
#         file_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
#         self.file_tree.configure(yscrollcommand=file_scrollbar.set)
        
#         # Pack treeview and scrollbar
#         self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
#         file_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
#         # Buttons
#         button_frame = tk.Frame(files_frame, bg='#f0f0f0')
#         button_frame.pack(pady=10)
        
#         ttk.Button(button_frame, text="🔄 Refresh", 
#                   command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
#         ttk.Button(button_frame, text="📂 Open Directory", 
#                   command=self.open_directory).pack(side=tk.LEFT, padx=5)
#         ttk.Button(button_frame, text="🗑️ Delete Selected", 
#                   command=self.delete_selected_file).pack(side=tk.LEFT, padx=5)
    
#     def create_status_tab(self):
#         """Create status and log tab"""
#         status_frame = ttk.Frame(self.notebook)
#         self.notebook.add(status_frame, text="📊 Status & Logs")
        
#         # Title
#         ttk.Label(status_frame, text="System Status & Activity Log", style='Header.TLabel').pack(pady=10)
        
#         # Status information
#         status_info_frame = tk.LabelFrame(status_frame, text="Current Status", 
#                                          font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         status_info_frame.pack(fill=tk.X, padx=20, pady=10)
        
#         self.status_text = tk.Text(status_info_frame, height=6, font=('Courier', 9), 
#                                   bg='#f8f9fa', relief=tk.SUNKEN, bd=1)
#         self.status_text.pack(fill=tk.X, padx=10, pady=10)
        
#         # Activity log
#         log_frame = tk.LabelFrame(status_frame, text="Activity Log", 
#                                  font=('Arial', 10, 'bold'), bg='#f0f0f0', fg='#2c3e50')
#         log_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
#         self.log_text = scrolledtext.ScrolledText(log_frame, height=15, font=('Courier', 9), 
#                                                  bg='#ffffff', relief=tk.SUNKEN, bd=1)
#         self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
#         # Log controls
#         log_controls = tk.Frame(log_frame, bg='#f0f0f0')
#         log_controls.pack(fill=tk.X, padx=10, pady=5)
        
#         ttk.Button(log_controls, text="🗑️ Clear Log", 
#                   command=self.clear_log).pack(side=tk.LEFT, padx=5)
#         ttk.Button(log_controls, text="💾 Save Log", 
#                   command=self.save_log).pack(side=tk.LEFT, padx=5)
    
#     def create_status_bar(self):
#         """Create status bar at bottom"""
#         self.status_bar = tk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, 
#                                   bg='#e9ecef', font=('Arial', 9))
#         self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
#     def log_message(self, message):
#         """Add message to activity log"""
#         import datetime
#         timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
#         log_entry = f"[{timestamp}] {message}\n"
        
#         self.log_text.insert(tk.END, log_entry)
#         self.log_text.see(tk.END)
        
#         # Update status bar
#         self.status_bar.config(text=message)
    
#     def update_status(self):
#         """Update status information"""
#         # Update key status
#         if self.encryptor.key is None:
#             self.key_status_label.config(text="❌ No encryption key loaded", foreground='red')
#             key_status = "No key loaded"
#         else:
#             self.key_status_label.config(text="✅ Encryption key loaded and ready", foreground='green')
#             key_status = "Key loaded and ready"
        
#         # Update status text
#         self.status_text.delete(1.0, tk.END)
#         status_info = f"""🔑 Key Status: {key_status}
# 📁 Current Directory: {os.getcwd()}
# 📊 Files Summary:
#    • Total files: {len([f for f in os.listdir('.') if os.path.isfile(f)])}
#    • Encrypted files: {len([f for f in os.listdir('.') if f.endswith('.encrypted')])}
#    • Key files: {len([f for f in os.listdir('.') if f.endswith('.key')])}
# 💻 Python Version: {self.get_python_version()}
# 🔒 Encryption: AES-256 (Fernet)"""
        
#         self.status_text.insert(1.0, status_info)
        
#         # Refresh file lists
#         self.refresh_file_list()
#         self.refresh_encrypted_files()
    
#     def get_python_version(self):
#         """Get Python version"""
#         import sys
#         return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    
#     def generate_key(self):
#         """Generate new encryption key"""
#         try:
#             self.encryptor.generate_key()
#             self.log_message("✅ New encryption key generated successfully")
#             self.update_status()
#             messagebox.showinfo("Success", "New encryption key generated!\n\nRemember to save it using 'Save Key As...' button.")
#         except Exception as e:
#             self.log_message(f"❌ Key generation failed: {e}")
#             messagebox.showerror("Error", f"Failed to generate key:\n{e}")
    
#     def save_key(self):
#         """Save encryption key to file"""
#         if self.encryptor.key is None:
#             messagebox.showwarning("Warning", "No key to save! Generate a key first.")
#             return
        
#         filename = filedialog.asksaveasfilename(
#             title="Save Encryption Key",
#             defaultextension=".key",
#             filetypes=[("Key files", "*.key"), ("All files", "*.*")]
#         )
        
#         if filename:
#             if self.encryptor.save_key(filename):
#                 self.log_message(f"✅ Key saved to: {filename}")
#                 messagebox.showinfo("Success", f"Key saved successfully to:\n{filename}")
#                 self.update_status()
#             else:
#                 self.log_message(f"❌ Failed to save key to: {filename}")
#                 messagebox.showerror("Error", "Failed to save key file!")
    
#     def load_key(self):
#         """Load encryption key from file"""
#         filename = filedialog.askopenfilename(
#             title="Load Encryption Key",
#             filetypes=[("Key files", "*.key"), ("All files", "*.*")]
#         )
        
#         if filename:
#             if self.encryptor.load_key(filename):
#                 self.log_message(f"✅ Key loaded from: {filename}")
#                 messagebox.showinfo("Success", f"Key loaded successfully from:\n{filename}")
#                 self.update_status()
#             else:
#                 self.log_message(f"❌ Failed to load key from: {filename}")
#                 messagebox.showerror("Error", "Failed to load key file!")
    
#     def quick_load_key(self):
#         """Quick load key from available key files"""
#         key_files = [f for f in os.listdir('.') if f.endswith('.key')]
        
#         if not key_files:
#             messagebox.showinfo("Info", "No key files found in current directory.")
#             return
        
#         # Create selection dialog
#         selection_window = tk.Toplevel(self.root)
#         selection_window.title("Select Key File")
#         selection_window.geometry("400x300")
#         selection_window.configure(bg='#f0f0f0')
        
#         tk.Label(selection_window, text="Select a key file to load:", 
#                 font=('Arial', 12, 'bold'), bg='#f0f0f0').pack(pady=10)
        
#         key_listbox = tk.Listbox(selection_window, font=('Arial', 10))
#         key_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
#         for key_file in key_files:
#             key_listbox.insert(tk.END, key_file)
        
#         def load_selected():
#             selection = key_listbox.curselection()
#             if selection:
#                 selected_key = key_files[selection[0]]
#                 if self.encryptor.load_key(selected_key):
#                     self.log_message(f"✅ Key loaded from: {selected_key}")
#                     messagebox.showinfo("Success", f"Key loaded from: {selected_key}")
#                     self.update_status()
#                     selection_window.destroy()
#                 else:
#                     messagebox.showerror("Error", "Failed to load selected key!")
        
#         button_frame = tk.Frame(selection_window, bg='#f0f0f0')
#         button_frame.pack(pady=10)
        
#         ttk.Button(button_frame, text="Load Selected", command=load_selected).pack(side=tk.LEFT, padx=5)
#         ttk.Button(button_frame, text="Cancel", command=selection_window.destroy).pack(side=tk.LEFT, padx=5)
    
#     def browse_encrypt_file(self):
#         """Browse for file to encrypt"""
#         filename = filedialog.askopenfilename(
#             title="Select File to Encrypt",
#             filetypes=[("All files", "*.*")]
#         )
        
#         if filename:
#             self.encrypt_file_var.set(filename)
    
#     def toggle_custom_output(self):
#         """Toggle custom output filename entry"""
#         if self.custom_output_var.get():
#             self.custom_output_entry.config(state='normal')
#         else:
#             self.custom_output_entry.config(state='disabled')
    
#     def encrypt_file(self):
#         """Encrypt selected file"""
#         if self.encryptor.key is None:
#             messagebox.showwarning("Warning", "No encryption key loaded!\n\nPlease generate or load a key first.")
#             return
        
#         input_file = self.encrypt_file_var.get().strip()
#         if not input_file:
#             messagebox.showwarning("Warning", "Please select a file to encrypt!")
#             return
        
#         if not os.path.exists(input_file):
#             messagebox.showerror("Error", f"File not found:\n{input_file}")
#             return
        
#         # Determine output filename
#         output_file = None
#         if self.custom_output_var.get():
#             output_file = self.custom_output_entry.get().strip()
#             if not output_file:
#                 messagebox.showwarning("Warning", "Please enter a custom output filename!")
#                 return
        
#         try:
#             # Show progress
#             self.encrypt_progress.start()
#             self.encrypt_button.config(state='disabled')
#             self.root.update()
            
#             # Encrypt file
#             result = self.encryptor.encrypt_file(input_file, output_file)
            
#             if result:
#                 self.log_message(f"✅ File encrypted: {input_file} -> {result}")
                
#                 # Delete original if requested
#                 if self.delete_original_var.get():
#                     try:
#                         os.remove(input_file)
#                         self.log_message(f"🗑️ Original file deleted: {input_file}")
#                     except Exception as e:
#                         self.log_message(f"⚠️ Could not delete original file: {e}")
                
#                 messagebox.showinfo("Success", f"File encrypted successfully!\n\nEncrypted file: {result}")
#                 self.update_status()
                
#                 # Clear form
#                 self.encrypt_file_var.set("")
#                 self.custom_output_entry.delete(0, tk.END)
#                 self.delete_original_var.set(False)
#                 self.custom_output_var.set(False)
#                 self.toggle_custom_output()
#             else:
#                 self.log_message(f"❌ Encryption failed for: {input_file}")
#                 messagebox.showerror("Error", "Encryption failed!")
        
#         except Exception as e:
#             self.log_message(f"❌ Encryption error: {e}")
#             messagebox.showerror("Error", f"Encryption failed:\n{e}")
        
#         finally:
#             # Hide progress
#             self.encrypt_progress.stop()
#             self.encrypt_button.config(state='normal')
    
#     def browse_decrypt_file(self):
#         """Browse for file to decrypt"""
#         filename = filedialog.askopenfilename(
#             title="Select Encrypted File to Decrypt",
#             filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
#         )
        
#         if filename:
#             self.decrypt_file_var.set(filename)
    
#     def refresh_encrypted_files(self):
#         """Refresh list of encrypted files"""
#         self.encrypted_files_listbox.delete(0, tk.END)
        
#         encrypted_files = [f for f in os.listdir('.') if f.endswith('.encrypted')]
        
#         if encrypted_files:
#             for file in encrypted_files:
#                 self.encrypted_files_listbox.insert(tk.END, file)
#         else:
#             self.encrypted_files_listbox.insert(tk.END, "No encrypted files found")
    
#     def select_encrypted_file(self, event):
#         """Select encrypted file from list"""
#         selection = self.encrypted_files_listbox.curselection()
#         if selection:
#             selected_file = self.encrypted_files_listbox.get(selection[0])
#             if selected_file != "No encrypted files found":
#                 self.decrypt_file_var.set(selected_file)
    
#     def decrypt_file(self):
#         """Decrypt selected file"""
#         if self.encryptor.key is None:
#             messagebox.showwarning("Warning", "No decryption key loaded!\n\nPlease load the correct encryption key first.")
#             return
        
#         input_file = self.decrypt_file_var.get().strip()
#         if not input_file:
#             messagebox.showwarning("Warning", "Please select an encrypted file to decrypt!")
#             return
        
#         if not os.path.exists(input_file):
#             messagebox.showerror("Error", f"File not found:\n{input_file}")
#             return
        
#         try:
#             # Show progress
#             self.decrypt_progress.start()
#             self.decrypt_button.config(state='disabled')
#             self.root.update()
            
#             # Decrypt file
#             result = self.encryptor.decrypt_file(input_file)
            
#             if result:
#                 self.log_message(f"✅ File decrypted: {input_file} -> {result}")
#                 messagebox.showinfo("Success", f"File decrypted successfully!\n\nDecrypted file: {result}")
#                 self.update_status()
                
#                 # Clear form
#                 self.decrypt_file_var.set("")
#             else:
#                 self.log_message(f"❌ Decryption failed for: {input_file}")
#                 messagebox.showerror("Error", "Decryption failed!\n\nThis could mean:\n• Wrong encryption key\n• Corrupted file\n• File wasn't encrypted with this tool")
        
#         except Exception as e:
#             self.log_message(f"❌ Decryption error: {e}")
#             messagebox.showerror("Error", f"Decryption failed:\n{e}")
        
#         finally:
#             # Hide progress
#             self.decrypt_progress.stop()
#             self.decrypt_button.config(state='normal')
    
#     def refresh_file_list(self):
#         """Refresh file list in file manager"""
#         # Clear existing items
#         for item in self.file_tree.get_children():
#             self.file_tree.delete(item)
        
#         # Get files
#         try:
#             files = os.listdir('.')
            
#             for file in files:
#                 if os.path.isfile(file):
#                     # Determine file type
#                     if file.endswith('.encrypted'):
#                         file_type = "🔒 Encrypted File"
#                     elif file.endswith('.key'):
#                         file_type = "🔑 Key File"
#                     elif file.endswith('.py'):
#                         file_type = "🐍 Python File"
#                     elif file.endswith('.txt'):
#                         file_type = "📄 Text File"
#                     else:
#                         file_type = "📁 File"
                    
#                     # Get file size
#                     size = os.path.getsize(file)
#                     if size < 1024:
#                         size_str = f"{size} B"
#                     elif size < 1024 * 1024:
#                         size_str = f"{size / 1024:.1f} KB"
#                     else:
#                         size_str = f"{size / (1024 * 1024):.1f} MB"
                    
#                     # Insert into tree
#                     self.file_tree.insert('', tk.END, values=(file, file_type, size_str))
        
#         except Exception as e:
#             self.log_message(f"❌ Error refreshing file list: {e}")
    
#     def open_directory(self):
#         """Open current directory in file explorer"""
#         import subprocess
#         import platform
        
#         try:
#             if platform.system() == "Windows":
#                 subprocess.run(["explorer", "."])
#             elif platform.system() == "Darwin":  # macOS
#                 subprocess.run(["open", "."])
#             else:  # Linux
#                 subprocess.run(["xdg-open", "."])
            
#             self.log_message("📂 Directory opened in file explorer")
#         except Exception as e:
#             self.log_message(f"❌ Error opening directory: {e}")
#             messagebox.showerror("Error", f"Could not open directory:\n{e}")
    
#     def delete_selected_file(self):
#         """Delete selected file"""
#         selection = self.file_tree.selection()
#         if not selection:
#             messagebox.showwarning("Warning", "Please select a file to delete!")
#             return
        
#         # Get selected file name
#         item = self.file_tree.item(selection[0])
#         filename = item['values'][0]
        
#         # Confirm deletion
#         if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete:\n{filename}\n\nThis action cannot be undone!"):
#             try:
#                 os.remove(filename)
#                 self.log_message(f"🗑️ File deleted: {filename}")
#                 self.refresh_file_list()
#                 self.update_status()
#                 messagebox.showinfo("Success", f"File deleted successfully:\n{filename}")
#             except Exception as e:
#                 self.log_message(f"❌ Error deleting file: {e}")
#                 messagebox.showerror("Error", f"Could not delete file:\n{e}")
    
#     def clear_log(self):
#         """Clear activity log"""
#         self.log_text.delete(1.0, tk.END)
#         self.log_message("🗑️ Activity log cleared")
    
#     def save_log(self):
#         """Save activity log to file"""
#         filename = filedialog.asksaveasfilename(
#             title="Save Activity Log",
#             defaultextension=".txt",
#             filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
#         )
        
#         if filename:
#             try:
#                 with open(filename, 'w') as f:
#                     f.write(self.log_text.get(1.0, tk.END))
                
#                 self.log_message(f"💾 Log saved to: {filename}")
#                 messagebox.showinfo("Success", f"Log saved successfully to:\n{filename}")
#             except Exception as e:
#                 self.log_message(f"❌ Error saving log: {e}")
#                 messagebox.showerror("Error", f"Could not save log:\n{e}")

# def main():
#     """Main function to run the GUI"""
#     root = tk.Tk()
#     app = FileEncryptionGUI(root)
    
#     # Log startup
#     app.log_message("🚀 File Encryption Tool started")
#     app.log_message("📋 GUI interface loaded successfully")
    
#     # Center window on screen
#     root.eval('tk::PlaceWindow . center')
    
#     # Start the GUI
#     root.mainloop()

# if __name__ == "__main__":
#     main()

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, simpledialog
import os
import threading
import base64
from encryption_module import AdvancedFileEncryptor

class AdvancedFileEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Advanced File Encryption Tool - Password Protected")
        self.root.geometry("900x700")
        self.root.configure(bg='#2c3e50')
        
        # Create encryptor instance
        self.encryptor = AdvancedFileEncryptor()
        
        # Password variables
        self.current_password = None
        self.password_strength = None
        
        # Configure style
        self.setup_styles()
        
        # Create GUI elements
        self.create_widgets()
        
        # Update status
        self.update_status()
    
    def setup_styles(self):
        """Configure modern GUI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure modern styles
        style.configure('Title.TLabel', font=('Segoe UI', 16, 'bold'), background='#2c3e50', foreground='white')
        style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), background='#ecf0f1', foreground='#2c3e50')
        style.configure('Status.TLabel', font=('Segoe UI', 10), background='#ecf0f1', foreground='#34495e')
        style.configure('Success.TButton', font=('Segoe UI', 10, 'bold'), foreground='#27ae60')
        style.configure('Danger.TButton', font=('Segoe UI', 10, 'bold'), foreground='#e74c3c')
        style.configure('Warning.TButton', font=('Segoe UI', 10, 'bold'), foreground='#f39c12')
        
        # Configure notebook style
        style.configure('TNotebook', background='#ecf0f1', borderwidth=0)
        style.configure('TNotebook.Tab', padding=[20, 10], font=('Segoe UI', 10, 'bold'))
    
    def create_widgets(self):
        """Create all GUI widgets with modern design"""
        # Main title header
        title_frame = tk.Frame(self.root, bg='#2c3e50', height=100)
        title_frame.pack(fill=tk.X, padx=0, pady=0)
        title_frame.pack_propagate(False)
        
        # Main title with modern styling
        title_label = tk.Label(title_frame, text="🔐 ADVANCED FILE ENCRYPTION TOOL", 
                              font=('Segoe UI', 20, 'bold'), fg='white', bg='#2c3e50')
        title_label.pack(pady=(15, 0))
        
        subtitle_label = tk.Label(title_frame, text="Password-Protected • Operating Systems Project • AES-256 Encryption", 
                                 font=('Segoe UI', 11), fg='#bdc3c7', bg='#2c3e50')
        subtitle_label.pack(pady=(5, 15))
        
        # Main content frame
        main_frame = tk.Frame(self.root, bg='#ecf0f1')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        # Create tabs
        self.create_password_tab()
        self.create_key_management_tab()
        self.create_encryption_tab()
        self.create_decryption_tab()
        self.create_batch_operations_tab()
        self.create_file_manager_tab()
        self.create_analytics_tab()
        self.create_status_tab()
        
        # Status bar at bottom
        self.create_status_bar()
    
    def create_password_tab(self):
        """Create password management tab"""
        password_frame = ttk.Frame(self.notebook)
        self.notebook.add(password_frame, text="🔑 Password & Security")
        
        # Title
        title_label = tk.Label(password_frame, text="Password-Based Encryption", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # Password setup section
        setup_frame = tk.LabelFrame(password_frame, text="🔐 Set Master Password", 
                                   font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50', 
                                   relief=tk.GROOVE, bd=2)
        setup_frame.pack(fill=tk.X, padx=30, pady=10)
        
        # Password entry with strength meter
        password_container = tk.Frame(setup_frame, bg='#ecf0f1')
        password_container.pack(fill=tk.X, padx=15, pady=15)
        
        tk.Label(password_container, text="Enter Master Password:", 
                font=('Segoe UI', 10, 'bold'), bg='#ecf0f1', fg='#2c3e50').pack(anchor=tk.W, pady=(0, 5))
        
        password_input_frame = tk.Frame(password_container, bg='#ecf0f1')
        password_input_frame.pack(fill=tk.X, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(password_input_frame, textvariable=self.password_var, 
                                      font=('Segoe UI', 11), show="*", width=40, relief=tk.SOLID, bd=1)
        self.password_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # Show/Hide password button
        self.show_password_var = tk.BooleanVar()
        self.show_password_btn = tk.Checkbutton(password_input_frame, text="👁 Show", 
                                               variable=self.show_password_var,
                                               command=self.toggle_password_visibility,
                                               bg='#ecf0f1', font=('Segoe UI', 9))
        self.show_password_btn.pack(side=tk.LEFT)
        
        # Password strength meter
        strength_frame = tk.Frame(password_container, bg='#ecf0f1')
        strength_frame.pack(fill=tk.X, pady=(10, 5))
        
        tk.Label(strength_frame, text="Password Strength:", 
                font=('Segoe UI', 9, 'bold'), bg='#ecf0f1', fg='#2c3e50').pack(side=tk.LEFT)
        
        self.strength_label = tk.Label(strength_frame, text="Not Set", 
                                      font=('Segoe UI', 9, 'bold'), bg='#ecf0f1', fg='#95a5a6')
        self.strength_label.pack(side=tk.LEFT, padx=(10, 0))
        
        # Strength progress bar
        self.strength_progress = ttk.Progressbar(password_container, length=300, mode='determinate')
        self.strength_progress.pack(fill=tk.X, pady=5)
        
        # Password feedback
        self.feedback_label = tk.Label(password_container, text="", 
                                      font=('Segoe UI', 9), bg='#ecf0f1', fg='#7f8c8d', 
                                      wraplength=400, justify=tk.LEFT)
        self.feedback_label.pack(fill=tk.X, pady=5)
        
        # Set password button
        ttk.Button(setup_frame, text="🔒 Set Master Password", 
                  command=self.set_master_password, style='Success.TButton').pack(pady=15)
        
        # Security status section
        security_frame = tk.LabelFrame(password_frame, text="🛡️ Security Status", 
                                      font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                      relief=tk.GROOVE, bd=2)
        security_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.security_text = tk.Text(security_frame, height=8, font=('Courier New', 10), 
                                    bg='#f8f9fa', relief=tk.SOLID, bd=1, wrap=tk.WORD)
        self.security_text.pack(fill=tk.X, padx=15, pady=15)
        
        # Security actions
        security_actions = tk.Frame(security_frame, bg='#ecf0f1')
        security_actions.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        ttk.Button(security_actions, text="🔄 Reset Failed Attempts", 
                  command=self.reset_failed_attempts).pack(side=tk.LEFT, padx=5)
        ttk.Button(security_actions, text="🧹 Clear Sensitive Data", 
                  command=self.clear_sensitive_data).pack(side=tk.LEFT, padx=5)
    
    def create_key_management_tab(self):
        """Create enhanced key management tab"""
        key_frame = ttk.Frame(self.notebook)
        self.notebook.add(key_frame, text="🗝️ Key Management")
        
        # Title
        title_label = tk.Label(key_frame, text="Encryption Key Management", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # Generate key section with modern styling
        gen_frame = tk.LabelFrame(key_frame, text="🔑 Key Generation", 
                                 font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                 relief=tk.GROOVE, bd=2)
        gen_frame.pack(fill=tk.X, padx=30, pady=10)
        
        tk.Label(gen_frame, text="Generate encryption keys for file security:", 
                font=('Segoe UI', 10), bg='#ecf0f1', fg='#34495e').pack(pady=(10, 5))
        
        gen_buttons = tk.Frame(gen_frame, bg='#ecf0f1')
        gen_buttons.pack(pady=15)
        
        ttk.Button(gen_buttons, text="🎲 Random Key", 
                  command=self.generate_random_key, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(gen_buttons, text="🔐 From Password", 
                  command=self.generate_from_password, style='Success.TButton').pack(side=tk.LEFT, padx=5)
        ttk.Button(gen_buttons, text="💾 Save Key", 
                  command=self.save_key_protected, style='Warning.TButton').pack(side=tk.LEFT, padx=5)
        
        # Load key section
        load_frame = tk.LabelFrame(key_frame, text="📂 Key Loading", 
                                  font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                  relief=tk.GROOVE, bd=2)
        load_frame.pack(fill=tk.X, padx=30, pady=10)
        
        load_buttons = tk.Frame(load_frame, bg='#ecf0f1')
        load_buttons.pack(pady=15)
        
        ttk.Button(load_buttons, text="📁 Load Key File", 
                  command=self.load_key_protected).pack(side=tk.LEFT, padx=5)
        ttk.Button(load_buttons, text="⚡ Quick Load", 
                  command=self.quick_load_key_protected).pack(side=tk.LEFT, padx=5)
        
        # Key status with enhanced display
        self.key_status_frame = tk.LabelFrame(key_frame, text="📊 Current Key Status", 
                                             font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                             relief=tk.GROOVE, bd=2)
        self.key_status_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.key_status_text = tk.Text(self.key_status_frame, height=6, font=('Courier New', 10), 
                                      bg='#f8f9fa', relief=tk.SOLID, bd=1)
        self.key_status_text.pack(fill=tk.X, padx=15, pady=15)
    
    def create_encryption_tab(self):
        """Create enhanced encryption tab"""
        encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(encrypt_frame, text="🔒 Encrypt Files")
        
        # Title
        title_label = tk.Label(encrypt_frame, text="File Encryption with Password Protection", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # File selection with drag & drop visual
        select_frame = tk.LabelFrame(encrypt_frame, text="📁 Select File to Encrypt", 
                                    font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                    relief=tk.GROOVE, bd=2)
        select_frame.pack(fill=tk.X, padx=30, pady=10)
        
        file_input_frame = tk.Frame(select_frame, bg='#ecf0f1')
        file_input_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.encrypt_file_var = tk.StringVar()
        self.encrypt_file_entry = tk.Entry(file_input_frame, textvariable=self.encrypt_file_var, 
                                          font=('Segoe UI', 11), width=60, relief=tk.SOLID, bd=1)
        self.encrypt_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(file_input_frame, text="📂 Browse", 
                  command=self.browse_encrypt_file).pack(side=tk.RIGHT)
        
        # Password options
        password_options_frame = tk.LabelFrame(encrypt_frame, text="🔐 Password Options", 
                                              font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                              relief=tk.GROOVE, bd=2)
        password_options_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.use_password_var = tk.BooleanVar(value=True)
        password_check = tk.Checkbutton(password_options_frame, text="🔒 Use password-based encryption (Recommended)", 
                                       variable=self.use_password_var, font=('Segoe UI', 10, 'bold'),
                                       bg='#ecf0f1', fg='#27ae60', command=self.toggle_password_encryption)
        password_check.pack(anchor=tk.W, padx=15, pady=10)
        
        self.encrypt_password_frame = tk.Frame(password_options_frame, bg='#ecf0f1')
        self.encrypt_password_frame.pack(fill=tk.X, padx=30, pady=(0, 15))
        
        tk.Label(self.encrypt_password_frame, text="Encryption Password:", 
                font=('Segoe UI', 10), bg='#ecf0f1', fg='#2c3e50').pack(anchor=tk.W)
        
        self.encrypt_password_var = tk.StringVar()
        self.encrypt_password_entry = tk.Entry(self.encrypt_password_frame, 
                                              textvariable=self.encrypt_password_var, 
                                              font=('Segoe UI', 11), show="*", width=40,
                                              relief=tk.SOLID, bd=1)
        self.encrypt_password_entry.pack(anchor=tk.W, pady=5)
        
        # Encryption options
        options_frame = tk.LabelFrame(encrypt_frame, text="⚙️ Encryption Options", 
                                     font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                     relief=tk.GROOVE, bd=2)
        options_frame.pack(fill=tk.X, padx=30, pady=10)
        
        options_container = tk.Frame(options_frame, bg='#ecf0f1')
        options_container.pack(fill=tk.X, padx=15, pady=15)
        
        self.delete_original_var = tk.BooleanVar()
        tk.Checkbutton(options_container, text="🗑️ Delete original file after encryption", 
                      variable=self.delete_original_var, font=('Segoe UI', 10),
                      bg='#ecf0f1').pack(anchor=tk.W, pady=2)
        
        self.custom_output_var = tk.BooleanVar()
        self.custom_output_check = tk.Checkbutton(options_container, text="📝 Use custom output filename:", 
                                                 variable=self.custom_output_var, font=('Segoe UI', 10),
                                                 command=self.toggle_custom_output, bg='#ecf0f1')
        self.custom_output_check.pack(anchor=tk.W, pady=2)
        
        self.custom_output_entry = tk.Entry(options_container, font=('Segoe UI', 10), width=50, 
                                           state='disabled', relief=tk.SOLID, bd=1)
        self.custom_output_entry.pack(anchor=tk.W, padx=20, pady=2, fill=tk.X)
        
        # Encrypt button with progress
        action_frame = tk.Frame(encrypt_frame, bg='#ecf0f1')
        action_frame.pack(pady=20)
        
        self.encrypt_button = tk.Button(action_frame, text="🔒 ENCRYPT FILE", 
                                       command=self.encrypt_file_threaded, 
                                       font=('Segoe UI', 12, 'bold'), bg='#27ae60', fg='white',
                                       relief=tk.RAISED, bd=2, padx=30, pady=10)
        self.encrypt_button.pack()
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(encrypt_frame, mode='indeterminate')
        self.encrypt_progress.pack(fill=tk.X, padx=30, pady=(10, 20))
    
    def create_decryption_tab(self):
        """Create enhanced decryption tab"""
        decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(decrypt_frame, text="🔓 Decrypt Files")
        
        # Title
        title_label = tk.Label(decrypt_frame, text="File Decryption with Password Authentication", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # File selection
        select_frame = tk.LabelFrame(decrypt_frame, text="📁 Select Encrypted File", 
                                    font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                    relief=tk.GROOVE, bd=2)
        select_frame.pack(fill=tk.X, padx=30, pady=10)
        
        file_input_frame = tk.Frame(select_frame, bg='#ecf0f1')
        file_input_frame.pack(fill=tk.X, padx=15, pady=15)
        
        self.decrypt_file_var = tk.StringVar()
        self.decrypt_file_entry = tk.Entry(file_input_frame, textvariable=self.decrypt_file_var, 
                                          font=('Segoe UI', 11), width=60, relief=tk.SOLID, bd=1)
        self.decrypt_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        ttk.Button(file_input_frame, text="📂 Browse", 
                  command=self.browse_decrypt_file).pack(side=tk.RIGHT)
        
        # Password input for decryption
        password_frame = tk.LabelFrame(decrypt_frame, text="🔐 Authentication", 
                                      font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                      relief=tk.GROOVE, bd=2)
        password_frame.pack(fill=tk.X, padx=30, pady=10)
        
        password_container = tk.Frame(password_frame, bg='#ecf0f1')
        password_container.pack(fill=tk.X, padx=15, pady=15)
        
        tk.Label(password_container, text="Enter password (if file is password-protected):", 
                font=('Segoe UI', 10), bg='#ecf0f1', fg='#2c3e50').pack(anchor=tk.W, pady=(0, 5))
        
        self.decrypt_password_var = tk.StringVar()
        self.decrypt_password_entry = tk.Entry(password_container, 
                                              textvariable=self.decrypt_password_var, 
                                              font=('Segoe UI', 11), show="*", width=40,
                                              relief=tk.SOLID, bd=1)
        self.decrypt_password_entry.pack(anchor=tk.W, pady=5)
        
        # Quick select from encrypted files
        quick_frame = tk.LabelFrame(decrypt_frame, text="⚡ Quick Select", 
                                   font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                   relief=tk.GROOVE, bd=2)
        quick_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.encrypted_files_listbox = tk.Listbox(quick_frame, height=5, font=('Segoe UI', 10),
                                                 relief=tk.SOLID, bd=1, bg='#f8f9fa')
        self.encrypted_files_listbox.pack(fill=tk.X, padx=15, pady=10)
        self.encrypted_files_listbox.bind('<Double-1>', self.select_encrypted_file)
        
        ttk.Button(quick_frame, text="🔄 Refresh List", 
                  command=self.refresh_encrypted_files).pack(pady=(0, 15))
        
        # Decrypt button
        action_frame = tk.Frame(decrypt_frame, bg='#ecf0f1')
        action_frame.pack(pady=20)
        
        self.decrypt_button = tk.Button(action_frame, text="🔓 DECRYPT FILE", 
                                       command=self.decrypt_file_threaded, 
                                       font=('Segoe UI', 12, 'bold'), bg='#e74c3c', fg='white',
                                       relief=tk.RAISED, bd=2, padx=30, pady=10)
        self.decrypt_button.pack()
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(decrypt_frame, mode='indeterminate')
        self.decrypt_progress.pack(fill=tk.X, padx=30, pady=(10, 20))
    
    def create_batch_operations_tab(self):
        """Create batch operations tab"""
        batch_frame = ttk.Frame(self.notebook)
        self.notebook.add(batch_frame, text="📦 Batch Operations")
        
        # Title
        title_label = tk.Label(batch_frame, text="Batch File Processing", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # Batch encryption section
        encrypt_batch_frame = tk.LabelFrame(batch_frame, text="🔒 Batch Encryption", 
                                           font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                           relief=tk.GROOVE, bd=2)
        encrypt_batch_frame.pack(fill=tk.X, padx=30, pady=10)
        
        # File selection for batch
        batch_select_frame = tk.Frame(encrypt_batch_frame, bg='#ecf0f1')
        batch_select_frame.pack(fill=tk.X, padx=15, pady=15)
        
        ttk.Button(batch_select_frame, text="📁 Add Files for Batch Encryption", 
                  command=self.add_batch_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(batch_select_frame, text="🗑️ Clear List", 
                  command=self.clear_batch_list).pack(side=tk.LEFT, padx=5)
        
        # Batch file list
        self.batch_files_listbox = tk.Listbox(encrypt_batch_frame, height=8, font=('Segoe UI', 10),
                                             relief=tk.SOLID, bd=1, bg='#f8f9fa')
        self.batch_files_listbox.pack(fill=tk.X, padx=15, pady=10)
        
        # Batch password
        batch_password_frame = tk.Frame(encrypt_batch_frame, bg='#ecf0f1')
        batch_password_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        tk.Label(batch_password_frame, text="Batch Encryption Password:", 
                font=('Segoe UI', 10, 'bold'), bg='#ecf0f1', fg='#2c3e50').pack(anchor=tk.W)
        
        self.batch_password_var = tk.StringVar()
        self.batch_password_entry = tk.Entry(batch_password_frame, 
                                            textvariable=self.batch_password_var, 
                                            font=('Segoe UI', 11), show="*", width=40,
                                            relief=tk.SOLID, bd=1)
        self.batch_password_entry.pack(anchor=tk.W, pady=5)
        
        # Batch encrypt button
        ttk.Button(encrypt_batch_frame, text="🔒 Encrypt All Files", 
                  command=self.batch_encrypt_files, style='Success.TButton').pack(pady=10)
        
        # Batch progress
        self.batch_progress = ttk.Progressbar(encrypt_batch_frame, mode='determinate')
        self.batch_progress.pack(fill=tk.X, padx=15, pady=5)
        
        self.batch_status_label = tk.Label(encrypt_batch_frame, text="Ready for batch processing", 
                                          font=('Segoe UI', 10), bg='#ecf0f1', fg='#7f8c8d')
        self.batch_status_label.pack(pady=5)
    
    def create_file_manager_tab(self):
        """Create enhanced file manager tab"""
        files_frame = ttk.Frame(self.notebook)
        self.notebook.add(files_frame, text="📂 File Manager")
        
        # Title
        title_label = tk.Label(files_frame, text="Advanced File Manager", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # File manager with enhanced features
        manager_frame = tk.LabelFrame(files_frame, text="📁 Directory Contents", 
                                     font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                     relief=tk.GROOVE, bd=2)
        manager_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        
        # File tree with enhanced columns
        columns = ('Name', 'Type', 'Size', 'Modified', 'Status')
        self.file_tree = ttk.Treeview(manager_frame, columns=columns, show='headings', height=18)
        
        # Configure columns
        self.file_tree.heading('Name', text='File Name')
        self.file_tree.heading('Type', text='Type')
        self.file_tree.heading('Size', text='Size')
        self.file_tree.heading('Modified', text='Modified')
        self.file_tree.heading('Status', text='Security Status')
        
        self.file_tree.column('Name', width=300)
        self.file_tree.column('Type', width=120)
        self.file_tree.column('Size', width=80)
        self.file_tree.column('Modified', width=120)
        self.file_tree.column('Status', width=120)
        
        # Scrollbars
        file_v_scrollbar = ttk.Scrollbar(manager_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        file_h_scrollbar = ttk.Scrollbar(manager_frame, orient=tk.HORIZONTAL, command=self.file_tree.xview)
        self.file_tree.configure(yscrollcommand=file_v_scrollbar.set, xscrollcommand=file_h_scrollbar.set)
        
        # Pack with scrollbars
        self.file_tree.grid(row=0, column=0, sticky='nsew', padx=15, pady=15)
        file_v_scrollbar.grid(row=0, column=1, sticky='ns', pady=15)
        file_h_scrollbar.grid(row=1, column=0, sticky='ew', padx=15)
        
        # Configure grid weights
        manager_frame.grid_rowconfigure(0, weight=1)
        manager_frame.grid_columnconfigure(0, weight=1)
        
        # File operations
        operations_frame = tk.Frame(files_frame, bg='#ecf0f1')
        operations_frame.pack(fill=tk.X, padx=30, pady=10)
        
        ttk.Button(operations_frame, text="🔄 Refresh", 
                  command=self.refresh_file_list).pack(side=tk.LEFT, padx=5)
        ttk.Button(operations_frame, text="📂 Open Directory", 
                  command=self.open_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(operations_frame, text="🗑️ Delete Selected", 
                  command=self.delete_selected_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(operations_frame, text="🔍 File Info", 
                  command=self.show_file_info).pack(side=tk.LEFT, padx=5)
    
    def create_analytics_tab(self):
        """Create analytics and statistics tab"""
        analytics_frame = ttk.Frame(self.notebook)
        self.notebook.add(analytics_frame, text="📊 Analytics")
        
        # Title
        title_label = tk.Label(analytics_frame, text="Security Analytics & Statistics", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # Statistics overview
        stats_frame = tk.LabelFrame(analytics_frame, text="📈 Operation Statistics", 
                                   font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                   relief=tk.GROOVE, bd=2)
        stats_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.stats_text = tk.Text(stats_frame, height=10, font=('Courier New', 10), 
                                 bg='#f8f9fa', relief=tk.SOLID, bd=1)
        self.stats_text.pack(fill=tk.X, padx=15, pady=15)
        
        # Operation history
        history_frame = tk.LabelFrame(analytics_frame, text="📋 Operation History", 
                                     font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                     relief=tk.GROOVE, bd=2)
        history_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        
        # History tree
        history_columns = ('Time', 'Operation', 'File', 'Status', 'Details')
        self.history_tree = ttk.Treeview(history_frame, columns=history_columns, show='headings', height=12)
        
        for col in history_columns:
            self.history_tree.heading(col, text=col)
            self.history_tree.column(col, width=120)
        
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=history_scrollbar.set)
        
        self.history_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=15, pady=15)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=15)
        
        # Analytics controls
        analytics_controls = tk.Frame(analytics_frame, bg='#ecf0f1')
        analytics_controls.pack(fill=tk.X, padx=30, pady=10)
        
        ttk.Button(analytics_controls, text="🔄 Refresh Analytics", 
                  command=self.refresh_analytics).pack(side=tk.LEFT, padx=5)
        ttk.Button(analytics_controls, text="📊 Export Report", 
                  command=self.export_analytics_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(analytics_controls, text="🗑️ Clear History", 
                  command=self.clear_operation_history).pack(side=tk.LEFT, padx=5)
    
    def create_status_tab(self):
        """Create enhanced status and log tab"""
        status_frame = ttk.Frame(self.notebook)
        self.notebook.add(status_frame, text="📋 System Status")
        
        # Title
        title_label = tk.Label(status_frame, text="System Status & Activity Monitor", 
                              font=('Segoe UI', 14, 'bold'), bg='#ecf0f1', fg='#2c3e50')
        title_label.pack(pady=(20, 10))
        
        # System information
        system_frame = tk.LabelFrame(status_frame, text="💻 System Information", 
                                    font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                    relief=tk.GROOVE, bd=2)
        system_frame.pack(fill=tk.X, padx=30, pady=10)
        
        self.system_info_text = tk.Text(system_frame, height=8, font=('Courier New', 10), 
                                       bg='#f8f9fa', relief=tk.SOLID, bd=1)
        self.system_info_text.pack(fill=tk.X, padx=15, pady=15)
        
        # Activity log with search
        log_frame = tk.LabelFrame(status_frame, text="📝 Activity Log", 
                                 font=('Segoe UI', 11, 'bold'), bg='#ecf0f1', fg='#2c3e50',
                                 relief=tk.GROOVE, bd=2)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=10)
        
        # Log search
        search_frame = tk.Frame(log_frame, bg='#ecf0f1')
        search_frame.pack(fill=tk.X, padx=15, pady=(15, 5))
        
        tk.Label(search_frame, text="🔍 Search:", 
                font=('Segoe UI', 10), bg='#ecf0f1', fg='#2c3e50').pack(side=tk.LEFT)
        
        self.log_search_var = tk.StringVar()
        self.log_search_entry = tk.Entry(search_frame, textvariable=self.log_search_var, 
                                        font=('Segoe UI', 10), width=30, relief=tk.SOLID, bd=1)
        self.log_search_entry.pack(side=tk.LEFT, padx=5)
        self.log_search_entry.bind('<KeyRelease>', self.search_log)
        
        ttk.Button(search_frame, text="Clear", 
                  command=lambda: self.log_search_var.set("")).pack(side=tk.LEFT, padx=5)
        
        # Activity log text
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, font=('Courier New', 10), 
                                                 bg='#ffffff', relief=tk.SOLID, bd=1)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=(5, 15))
        
        # Log controls
        log_controls = tk.Frame(log_frame, bg='#ecf0f1')
        log_controls.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        ttk.Button(log_controls, text="🗑️ Clear Log", 
                  command=self.clear_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="💾 Save Log", 
                  command=self.save_log).pack(side=tk.LEFT, padx=5)
        ttk.Button(log_controls, text="📧 Export Log", 
                  command=self.export_log).pack(side=tk.LEFT, padx=5)
    
    def create_status_bar(self):
        """Create enhanced status bar"""
        status_frame = tk.Frame(self.root, bg='#34495e', height=30)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)
        
        self.status_bar = tk.Label(status_frame, text="🔐 Advanced File Encryption Tool - Ready", 
                                  relief=tk.FLAT, anchor=tk.W, bg='#34495e', fg='white', 
                                  font=('Segoe UI', 9), padx=10)
        self.status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True, pady=5)
        
        # Security indicator
        self.security_indicator = tk.Label(status_frame, text="🛡️ Secure", 
                                          relief=tk.FLAT, bg='#27ae60', fg='white', 
                                          font=('Segoe UI', 9, 'bold'), padx=15)
        self.security_indicator.pack(side=tk.RIGHT, pady=5, padx=5)
    
    # Password and security methods
    def check_password_strength(self, event=None):
        """Check password strength in real-time"""
        password = self.password_var.get()
        if not password:
            self.strength_label.config(text="Not Set", fg='#95a5a6')
            self.strength_progress['value'] = 0
            self.feedback_label.config(text="")
            return
        
        strength = self.encryptor.validate_password_strength(password)
        
        # Update strength label with color
        colors = {'Weak': '#e74c3c', 'Medium': '#f39c12', 'Strong': '#3498db', 'Very Strong': '#27ae60'}
        self.strength_label.config(text=strength['strength'], fg=colors.get(strength['strength'], '#95a5a6'))
        
        # Update progress bar
        self.strength_progress['value'] = strength['percentage']
        
        # Update feedback
        if strength['feedback']:
            feedback_text = "Suggestions: " + ", ".join(strength['feedback'][:3])
            self.feedback_label.config(text=feedback_text, fg='#e67e22')
        else:
            self.feedback_label.config(text="✅ Strong password!", fg='#27ae60')
        
        self.password_strength = strength
    
    def toggle_password_visibility(self):
        """Toggle password visibility"""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def set_master_password(self):
        """Set master password for encryption"""
        password = self.password_var.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password!")
            return
        
        if self.password_strength and self.password_strength['score'] < 2:
            if not messagebox.askyesno("Weak Password", 
                                      f"Password strength is {self.password_strength['strength']}.\n\n" +
                                      "Using a weak password reduces security.\n\n" +
                                      "Continue anyway?"):
                return
        
        try:
            self.encryptor.derive_key_from_password(password)
            self.current_password = password
            
            self.log_message("🔐 Master password set successfully")
            self.log_message(f"🔑 Key derived using Scrypt KDF")
            
            messagebox.showinfo("Success", "Master password set successfully!\n\nYou can now encrypt files with password protection.")
            
            # Clear password entry for security
            self.password_var.set("")
            self.update_status()
            
        except Exception as e:
            self.log_message(f"❌ Failed to set master password: {e}")
            messagebox.showerror("Error", f"Failed to set master password:\n{e}")
    
    def reset_failed_attempts(self):
        """Reset failed authentication attempts"""
        self.encryptor.reset_failed_attempts()
        self.log_message("🔄 Failed authentication attempts reset")
        self.update_security_status()
        messagebox.showinfo("Success", "Failed attempts counter has been reset.")
    
    def clear_sensitive_data(self):
        """Clear sensitive data from memory"""
        if messagebox.askyesno("Confirm", "This will clear all sensitive data from memory.\n\nContinue?"):
            self.encryptor.clear_sensitive_data()
            self.current_password = None
            self.log_message("🧹 Sensitive data cleared from memory")
            self.update_status()
            messagebox.showinfo("Success", "Sensitive data has been cleared from memory.")
    
    # Enhanced key management methods
    def generate_random_key(self):
        """Generate random encryption key"""
        try:
            self.encryptor.generate_key()
            self.log_message("✅ Random encryption key generated")
            self.update_status()
            messagebox.showinfo("Success", "Random encryption key generated!\n\nThis key is not password-protected.")
        except Exception as e:
            self.log_message(f"❌ Key generation failed: {e}")
            messagebox.showerror("Error", f"Failed to generate key:\n{e}")
    
    def generate_from_password(self):
        """Generate key from password"""
        password = simpledialog.askstring("Password", "Enter password for key derivation:", show='*')
        if password:
            try:
                self.encryptor.derive_key_from_password(password)
                self.current_password = password
                self.log_message("🔐 Key generated from password using Scrypt KDF")
                self.update_status()
                messagebox.showinfo("Success", "Encryption key generated from password!")
            except Exception as e:
                self.log_message(f"❌ Key derivation failed: {e}")
                messagebox.showerror("Error", f"Failed to derive key:\n{e}")
    
    def save_key_protected(self):
        """Save encryption key with optional password protection"""
        if self.encryptor.key is None:
            messagebox.showwarning("Warning", "No key to save! Generate a key first.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save Encryption Key",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            protect = messagebox.askyesno("Key Protection", "Do you want to password-protect this key file?")
            password = None
            
            if protect:
                password = simpledialog.askstring("Key Protection", "Enter password to protect key file:", show='*')
                if not password:
                    return
            
            try:
                if self.encryptor.save_key(filename, password):
                    self.log_message(f"✅ Key saved to: {filename}" + (" (password-protected)" if password else ""))
                    messagebox.showinfo("Success", f"Key saved successfully!\n\n{filename}" + 
                                      ("\n\nKey file is password-protected." if password else ""))
                    self.update_status()
                else:
                    self.log_message(f"❌ Failed to save key to: {filename}")
                    messagebox.showerror("Error", "Failed to save key file!")
            except Exception as e:
                self.log_message(f"❌ Error saving key: {e}")
                messagebox.showerror("Error", f"Failed to save key:\n{e}")
    
    def load_key_protected(self):
        """Load encryption key with optional password"""
        filename = filedialog.askopenfilename(
            title="Load Encryption Key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        
        if filename:
            # Try loading without password first
            try:
                if self.encryptor.load_key(filename):
                    self.log_message(f"✅ Key loaded from: {filename}")
                    messagebox.showinfo("Success", f"Key loaded successfully from:\n{filename}")
                    self.update_status()
                    return
            except:
                pass
            
            # If failed, ask for password
            password = simpledialog.askstring("Key Password", "Enter password for key file (or Cancel for unprotected):", show='*')
            
            try:
                if self.encryptor.load_key(filename, password):
                    self.log_message(f"✅ Protected key loaded from: {filename}")
                    messagebox.showinfo("Success", f"Key loaded successfully from:\n{filename}")
                    self.update_status()
                else:
                    self.log_message(f"❌ Failed to load key from: {filename}")
                    messagebox.showerror("Error", "Failed to load key file!\n\nCheck if password is correct.")
            except Exception as e:
                self.log_message(f"❌ Error loading key: {e}")
                messagebox.showerror("Error", f"Failed to load key:\n{e}")
    
    def quick_load_key_protected(self):
        """Quick load key from available key files with password support"""
        key_files = [f for f in os.listdir('.') if f.endswith('.key')]
        
        if not key_files:
            messagebox.showinfo("Info", "No key files found in current directory.")
            return
        
        # Create selection dialog
        selection_window = tk.Toplevel(self.root)
        selection_window.title("Select Key File")
        selection_window.geometry("500x400")
        selection_window.configure(bg='#ecf0f1')
        selection_window.transient(self.root)
        selection_window.grab_set()
        
        tk.Label(selection_window, text="Select a key file to load:", 
                font=('Segoe UI', 12, 'bold'), bg='#ecf0f1', fg='#2c3e50').pack(pady=15)
        
        key_listbox = tk.Listbox(selection_window, font=('Segoe UI', 10), 
                               relief=tk.SOLID, bd=1, bg='#f8f9fa', height=12)
        key_listbox.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        for key_file in key_files:
            key_listbox.insert(tk.END, key_file)
        
        def load_selected():
            selection = key_listbox.curselection()
            if selection:
                selected_key = key_files[selection[0]]
                
                # Try without password first
                try:
                    if self.encryptor.load_key(selected_key):
                        self.log_message(f"✅ Key loaded from: {selected_key}")
                        messagebox.showinfo("Success", f"Key loaded from: {selected_key}")
                        self.update_status()
                        selection_window.destroy()
                        return
                except:
                    pass
                
                # Ask for password
                password = simpledialog.askstring("Key Password", f"Enter password for {selected_key}:", show='*')
                
                try:
                    if self.encryptor.load_key(selected_key, password):
                        self.log_message(f"✅ Protected key loaded from: {selected_key}")
                        messagebox.showinfo("Success", f"Key loaded from: {selected_key}")
                        self.update_status()
                        selection_window.destroy()
                    else:
                        messagebox.showerror("Error", "Failed to load key!\n\nCheck password.")
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to load key:\n{e}")
        
        button_frame = tk.Frame(selection_window, bg='#ecf0f1')
        button_frame.pack(pady=15)
        
        ttk.Button(button_frame, text="Load Selected", command=load_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=selection_window.destroy).pack(side=tk.LEFT, padx=5)
    
    # Enhanced encryption methods
    def browse_encrypt_file(self):
        """Browse for file to encrypt"""
        filename = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[("All files", "*.*")]
        )
        
        if filename:
            self.encrypt_file_var.set(filename)
            self.log_message(f"📁 Selected file for encryption: {os.path.basename(filename)}")
    
    def toggle_password_encryption(self):
        """Toggle password encryption option"""
        if self.use_password_var.get():
            for widget in self.encrypt_password_frame.winfo_children():
                widget.configure(state='normal')
        else:
            for widget in self.encrypt_password_frame.winfo_children():
                if hasattr(widget, 'configure'):
                    try:
                        widget.configure(state='disabled')
                    except:
                        pass
    
    def toggle_custom_output(self):
        """Toggle custom output filename entry"""
        if self.custom_output_var.get():
            self.custom_output_entry.config(state='normal')
        else:
            self.custom_output_entry.config(state='disabled')
    
    def encrypt_file_threaded(self):
        """Encrypt file in separate thread to prevent GUI freezing"""
        thread = threading.Thread(target=self.encrypt_file_process, daemon=True)
        thread.start()
    
    def encrypt_file_process(self):
        """Process file encryption"""
        input_file = self.encrypt_file_var.get().strip()
        if not input_file:
            messagebox.showwarning("Warning", "Please select a file to encrypt!")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found:\n{input_file}")
            return
        
        # Get password if using password-based encryption
        password = None
        if self.use_password_var.get():
            password = self.encrypt_password_var.get().strip()
            if not password:
                messagebox.showwarning("Warning", "Please enter a password for encryption!")
                return
        elif self.encryptor.key is None:
            messagebox.showwarning("Warning", "No encryption key available!\n\nPlease generate a key or enter a password.")
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
            
            # Encrypt file
            result = self.encryptor.encrypt_file(input_file, password, output_file)
            
            if result:
                self.log_message(f"✅ File encrypted: {os.path.basename(input_file)} -> {os.path.basename(result)}")
                
                # Delete original if requested
                if self.delete_original_var.get():
                    try:
                        os.remove(input_file)
                        self.log_message(f"🗑️ Original file deleted: {os.path.basename(input_file)}")
                    except Exception as e:
                        self.log_message(f"⚠️ Could not delete original file: {e}")
                
                messagebox.showinfo("Success", f"File encrypted successfully!\n\n📁 Encrypted file: {os.path.basename(result)}" + 
                                  ("\n🔐 Password-protected encryption used" if password else "\n🔑 Key-based encryption used"))
                
                self.update_status()
                
                # Clear form
                self.encrypt_file_var.set("")
                self.encrypt_password_var.set("")
                self.custom_output_entry.delete(0, tk.END)
                self.delete_original_var.set(False)
                self.custom_output_var.set(False)
                self.toggle_custom_output()
            else:
                self.log_message(f"❌ Encryption failed for: {os.path.basename(input_file)}")
                messagebox.showerror("Error", "Encryption failed!")
        
        except Exception as e:
            self.log_message(f"❌ Encryption error: {e}")
            messagebox.showerror("Error", f"Encryption failed:\n{e}")
        
        finally:
            # Hide progress
            self.encrypt_progress.stop()
            self.encrypt_button.config(state='normal')
    
    # Enhanced decryption methods
    def browse_decrypt_file(self):
        """Browse for file to decrypt"""
        filename = filedialog.askopenfilename(
            title="Select Encrypted File to Decrypt",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        
        if filename:
            self.decrypt_file_var.set(filename)
            self.log_message(f"📁 Selected encrypted file: {os.path.basename(filename)}")
    
    def refresh_encrypted_files(self):
        """Refresh list of encrypted files"""
        self.encrypted_files_listbox.delete(0, tk.END)
        
        try:
            encrypted_files = [f for f in os.listdir('.') if f.endswith('.encrypted')]
            
            if encrypted_files:
                for file in encrypted_files:
                    # Get file size for display
                    try:
                        size = os.path.getsize(file)
                        if size < 1024:
                            size_str = f"{size}B"
                        elif size < 1024 * 1024:
                            size_str = f"{size/1024:.1f}KB"
                        else:
                            size_str = f"{size/(1024*1024):.1f}MB"
                        
                        display_text = f"{file} ({size_str})"
                        self.encrypted_files_listbox.insert(tk.END, display_text)
                    except:
                        self.encrypted_files_listbox.insert(tk.END, file)
            else:
                self.encrypted_files_listbox.insert(tk.END, "No encrypted files found")
        except Exception as e:
            self.log_message(f"❌ Error refreshing encrypted files list: {e}")
    
    def select_encrypted_file(self, event):
        """Select encrypted file from list"""
        selection = self.encrypted_files_listbox.curselection()
        if selection:
            selected_item = self.encrypted_files_listbox.get(selection[0])
            if selected_item != "No encrypted files found":
                # Extract filename (remove size info)
                filename = selected_item.split(' (')[0]
                self.decrypt_file_var.set(filename)
    
    def decrypt_file_threaded(self):
        """Decrypt file in separate thread"""
        thread = threading.Thread(target=self.decrypt_file_process, daemon=True)
        thread.start()
    
    def decrypt_file_process(self):
        """Process file decryption"""
        input_file = self.decrypt_file_var.get().strip()
        if not input_file:
            messagebox.showwarning("Warning", "Please select an encrypted file to decrypt!")
            return
        
        if not os.path.exists(input_file):
            messagebox.showerror("Error", f"File not found:\n{input_file}")
            return
        
        password = self.decrypt_password_var.get().strip() or None
        
        try:
            # Show progress
            self.decrypt_progress.start()
            self.decrypt_button.config(state='disabled')
            
            # Decrypt file
            result = self.encryptor.decrypt_file(input_file, password)
            
            if result:
                self.log_message(f"✅ File decrypted: {os.path.basename(input_file)} -> {os.path.basename(result)}")
                messagebox.showinfo("Success", f"File decrypted successfully!\n\n📁 Decrypted file: {os.path.basename(result)}")
                self.update_status()
                
                # Clear form
                self.decrypt_file_var.set("")
                self.decrypt_password_var.set("")
            else:
                self.log_message(f"❌ Decryption failed for: {os.path.basename(input_file)}")
                messagebox.showerror("Error", "Decryption failed!\n\nPossible reasons:\n• Wrong password\n• Wrong encryption key\n• Corrupted file\n• File not encrypted with this tool")
        
        except Exception as e:
            self.log_message(f"❌ Decryption error: {e}")
            if "Invalid password" in str(e) or "Invalid token" in str(e):
                messagebox.showerror("Authentication Failed", "❌ Invalid password!\n\nPlease check your password and try again.")
            else:
                messagebox.showerror("Error", f"Decryption failed:\n{e}")
        
        finally:
            # Hide progress
            self.decrypt_progress.stop()
            self.decrypt_button.config(state='normal')
    
    # Batch operations methods
    def add_batch_files(self):
        """Add files for batch processing"""
        filenames = filedialog.askopenfilenames(
            title="Select Files for Batch Encryption",
            filetypes=[("All files", "*.*")]
        )
        
        if filenames:
            for filename in filenames:
                # Check if already in list
                current_items = [self.batch_files_listbox.get(i) for i in range(self.batch_files_listbox.size())]
                if filename not in current_items:
                    self.batch_files_listbox.insert(tk.END, filename)
            
            self.log_message(f"📦 Added {len(filenames)} files to batch queue")
    
    def clear_batch_list(self):
        """Clear batch file list"""
        self.batch_files_listbox.delete(0, tk.END)
        self.log_message("🗑️ Batch file list cleared")
    
    def batch_encrypt_files(self):
        """Process batch file encryption"""
        files = [self.batch_files_listbox.get(i) for i in range(self.batch_files_listbox.size())]
        
        if not files:
            messagebox.showwarning("Warning", "No files selected for batch encryption!")
            return
        
        password = self.batch_password_var.get().strip()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password for batch encryption!")
            return
        
        # Process files in thread
        thread = threading.Thread(target=self.batch_encrypt_process, args=(files, password), daemon=True)
        thread.start()
    
    def batch_encrypt_process(self, files, password):
        """Process batch encryption"""
        total_files = len(files)
        successful = 0
        failed = 0
        
        self.batch_progress.config(mode='determinate', maximum=total_files)
        
        for i, file_path in enumerate(files):
            try:
                self.batch_status_label.config(text=f"Processing: {os.path.basename(file_path)} ({i+1}/{total_files})")
                self.root.update()
                
                result = self.encryptor.encrypt_file(file_path, password)
                if result:
                    successful += 1
                    self.log_message(f"✅ Batch encrypted: {os.path.basename(file_path)}")
                else:
                    failed += 1
                    self.log_message(f"❌ Batch encryption failed: {os.path.basename(file_path)}")
                
                self.batch_progress['value'] = i + 1
                
            except Exception as e:
                failed += 1
                self.log_message(f"❌ Batch encryption error: {os.path.basename(file_path)} - {e}")
        
        # Reset progress
        self.batch_progress['value'] = 0
        self.batch_status_label.config(text=f"Batch complete: {successful} successful, {failed} failed")
        
        # Show results
        messagebox.showinfo("Batch Processing Complete", 
                          f"Batch encryption completed!\n\n✅ Successful: {successful}\n❌ Failed: {failed}")
        
        self.log_message(f"📦 Batch encryption completed: {successful}/{total_files} successful")
        self.update_status()
    
    # Enhanced file manager methods
    def refresh_file_list(self):
        """Refresh file list with enhanced information"""
        # Clear existing items
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        try:
            files = os.listdir('.')
            
            for file in files:
                if os.path.isfile(file):
                    # Get file stats
                    stat = os.stat(file)
                    
                    # Determine file type and status
                    if file.endswith('.encrypted'):
                        file_type = "🔒 Encrypted"
                        status = "Protected"
                    elif file.endswith('.key'):
                        file_type = "🔑 Key File"
                        status = "Key Material"
                    elif file.endswith(('.py', '.pyw')):
                        file_type = "🐍 Python"
                        status = "Source Code"
                    elif file.endswith(('.txt', '.md', '.log')):
                        file_type = "📄 Text"
                        status = "Plain Text"
                    elif file.endswith(('.jpg', '.png', '.gif', '.bmp')):
                        file_type = "🖼️ Image"
                        status = "Media File"
                    elif file.endswith(('.doc', '.docx', '.pdf')):
                        file_type = "📋 Document"
                        status = "Document"
                    else:
                        file_type = "📁 File"
                        status = "Unknown"
                    
                    # Format file size
                    size = stat.st_size
                    if size < 1024:
                        size_str = f"{size} B"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f} KB"
                    elif size < 1024 * 1024 * 1024:
                        size_str = f"{size / (1024 * 1024):.1f} MB"
                    else:
                        size_str = f"{size / (1024 * 1024 * 1024):.1f} GB"
                    
                    # Format modification time
                    import datetime
                    mod_time = datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                    
                    # Insert into tree
                    self.file_tree.insert('', tk.END, values=(file, file_type, size_str, mod_time, status))
        
        except Exception as e:
            self.log_message(f"❌ Error refreshing file list: {e}")
    
    def open_directory(self):
        """Open current directory in system file explorer"""
        import subprocess
        import platform
        
        try:
            system = platform.system().lower()
            if system == "windows":
                subprocess.run(["explorer", "."])
            elif system == "darwin":  # macOS
                subprocess.run(["open", "."])
            else:  # Linux and others
                subprocess.run(["xdg-open", "."])
            
            self.log_message("📂 Directory opened in system file explorer")
        except Exception as e:
            self.log_message(f"❌ Error opening directory: {e}")
            messagebox.showerror("Error", f"Could not open directory:\n{e}")
    
    def delete_selected_file(self):
        """Delete selected file with confirmation"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file to delete!")
            return
        
        # Get selected file name
        item = self.file_tree.item(selection[0])
        filename = item['values'][0]
        
        # Enhanced confirmation dialog
        confirm_msg = f"Delete file: {filename}?\n\n⚠️ This action cannot be undone!"
        if filename.endswith('.encrypted'):
            confirm_msg += "\n\n🔒 This is an encrypted file."
        elif filename.endswith('.key'):
            confirm_msg += "\n\n🔑 This is a key file - be very careful!"
        
        if messagebox.askyesno("Confirm Deletion", confirm_msg):
            try:
                os.remove(filename)
                self.log_message(f"🗑️ File deleted: {filename}")
                self.refresh_file_list()
                self.update_status()
                messagebox.showinfo("Success", f"File deleted successfully:\n{filename}")
            except Exception as e:
                self.log_message(f"❌ Error deleting file: {e}")
                messagebox.showerror("Error", f"Could not delete file:\n{e}")
    
    def show_file_info(self):
        """Show detailed file information"""
        selection = self.file_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a file!")
            return
        
        item = self.file_tree.item(selection[0])
        filename = item['values'][0]
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", f"File not found: {filename}")
            return
        
        try:
            stat = os.stat(filename)
            import datetime
            import hashlib
            
            # Calculate file hash
            with open(filename, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()[:16]
            
            # Prepare info
            info = f"""File Information: {filename}
{'=' * 50}
📁 Full Path: {os.path.abspath(filename)}
📊 Size: {stat.st_size:,} bytes
📅 Created: {datetime.datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S")}
📝 Modified: {datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")}
👤 Owner: UID {stat.st_uid}
🔐 Hash (SHA-256): {file_hash}...
🔒 Permissions: {oct(stat.st_mode)[-3:]}

File Type Analysis:
{'-' * 30}"""
            
            if filename.endswith('.encrypted'):
                info += "\n🔒 Encrypted file - contains secured data"
            elif filename.endswith('.key'):
                info += "\n🔑 Encryption key file - highly sensitive!"
            else:
                info += f"\n📄 Regular file - {item['values'][1]}"
            
            # Show in dialog
            info_window = tk.Toplevel(self.root)
            info_window.title(f"File Info: {filename}")
            info_window.geometry("600x400")
            info_window.configure(bg='#ecf0f1')
            
            info_text = scrolledtext.ScrolledText(info_window, font=('Courier New', 10), 
                                                 bg='#f8f9fa', wrap=tk.WORD)
            info_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
            info_text.insert(tk.END, info)
            info_text.config(state=tk.DISABLED)
            
            ttk.Button(info_window, text="Close", command=info_window.destroy).pack(pady=10)
            
            self.log_message(f"ℹ️ Viewed file info: {filename}")
            
        except Exception as e:
            self.log_message(f"❌ Error getting file info: {e}")
            messagebox.showerror("Error", f"Could not get file information:\n{e}")
    
    # Analytics methods
    def refresh_analytics(self):
        """Refresh analytics and statistics"""
        try:
            # Get operation history
            history = self.encryptor.get_operation_history()
            security_status = self.encryptor.get_security_status()
            
            # Calculate statistics
            total_ops = len(history)
            successful_ops = len([op for op in history if op.get('success', True)])
            failed_ops = total_ops - successful_ops
            
            encryptions = len([op for op in history if op.get('type') == 'encryption'])
            decryptions = len([op for op in history if op.get('type') == 'decryption'])
            auth_failures = len([op for op in history if op.get('type') == 'authentication_failed'])
            
            # Update statistics display
            stats = f"""🔐 SECURITY ANALYTICS REPORT
{'=' * 50}

📊 OPERATION STATISTICS:
   • Total Operations: {total_ops}
   • Successful: {successful_ops} ({successful_ops/total_ops*100 if total_ops > 0 else 0:.1f}%)
   • Failed: {failed_ops} ({failed_ops/total_ops*100 if total_ops > 0 else 0:.1f}%)

🔒 OPERATION BREAKDOWN:
   • Encryptions: {encryptions}
   • Decryptions: {decryptions}
   • Authentication Failures: {auth_failures}

🛡️ SECURITY STATUS:
   • Key Status: {'✅ Loaded' if security_status['has_key'] else '❌ Not Loaded'}
   • Password Protection: {'✅ Enabled' if security_status['has_password'] else '❌ Disabled'}
   • Failed Attempts: {security_status['failed_attempts']}/{self.encryptor.max_failed_attempts}
   • Account Status: {'🔒 Locked' if security_status['is_locked_out'] else '✅ Active'}

📈 PERFORMANCE METRICS:
   • Success Rate: {successful_ops/total_ops*100 if total_ops > 0 else 0:.1f}%
   • Security Score: {'High' if auth_failures == 0 and security_status['has_password'] else 'Medium' if auth_failures < 3 else 'Low'}
"""
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats)
            
            # Update history tree
            for item in self.history_tree.get_children():
                self.history_tree.delete(item)
            
            for op in history[-50:]:  # Show last 50 operations
                timestamp = op.get('timestamp', 'Unknown')[:19]  # Remove microseconds
                operation = op.get('type', 'Unknown')
                file_name = op.get('file', 'N/A')
                status = '✅ Success' if op.get('success', True) else '❌ Failed'
                details = op.get('error', '') or f"{op.get('size', 0)} bytes"
                
                self.history_tree.insert('', 0, values=(timestamp, operation, file_name, status, details))
            
            self.log_message("📊 Analytics refreshed")
            
        except Exception as e:
            self.log_message(f"❌ Error refreshing analytics: {e}")
    
    def export_analytics_report(self):
        """Export analytics report to file"""
        filename = filedialog.asksaveasfilename(
            title="Save Analytics Report",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                # Get current stats
                self.refresh_analytics()
                stats_content = self.stats_text.get(1.0, tk.END)
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"File Encryption Tool - Security Analytics Report\n")
                    f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(stats_content)
                    f.write("\n\nDETAILED OPERATION HISTORY:\n")
                    f.write("=" * 60 + "\n")
                    
                    # Add detailed history
                    history = self.encryptor.get_operation_history()
                    for op in history:
                        f.write(f"{op.get('timestamp', 'Unknown')} | {op.get('type', 'Unknown')} | "
                               f"{op.get('file', 'N/A')} | {'Success' if op.get('success', True) else 'Failed'}")
                        if op.get('error'):
                            f.write(f" | Error: {op['error']}")
                        f.write("\n")
                
                self.log_message(f"📊 Analytics report exported: {filename}")
                messagebox.showinfo("Success", f"Analytics report exported to:\n{filename}")
                
            except Exception as e:
                self.log_message(f"❌ Error exporting analytics: {e}")
                messagebox.showerror("Error", f"Failed to export analytics:\n{e}")
    
    def clear_operation_history(self):
        """Clear operation history"""
        if messagebox.askyesno("Confirm", "Clear all operation history?\n\nThis action cannot be undone."):
            self.encryptor.operation_history.clear()
            self.refresh_analytics()
            self.log_message("🗑️ Operation history cleared")
            messagebox.showinfo("Success", "Operation history has been cleared.")
    
    # Enhanced status and logging methods
    def update_status(self):
        """Update all status information"""
        self.update_key_status()
        self.update_security_status()
        self.update_system_info()
        self.refresh_file_list()
        self.refresh_encrypted_files()
        self.refresh_analytics()
    
    def update_key_status(self):
        """Update key status display"""
        status_text = ""
        
        if self.encryptor.key is None:
            status_text = "🔑 Status: No encryption key loaded\n"
            status_text += "⚠️  Generate or load a key to begin encryption\n"
            self.security_indicator.config(text="🔓 No Key", bg='#e74c3c')
        else:
            status_text = "🔑 Status: Encryption key loaded and ready\n"
            
            if self.encryptor.password_hash:
                status_text += "🔐 Type: Password-derived key (Scrypt KDF)\n"
                status_text += f"🧂 Salt: {base64.b64encode(self.encryptor.salt).decode()[:16]}...\n"
            else:
                status_text += "🎲 Type: Randomly generated key\n"
            
            if self.encryptor.creation_time:
                status_text += f"📅 Created: {self.encryptor.creation_time[:19]}\n"
            
            self.security_indicator.config(text="🛡️ Secure", bg='#27ae60')
        
        status_text += f"\n🔒 Algorithm: Fernet (AES-128 + HMAC-SHA256)\n"
        status_text += f"💾 Key Length: 256 bits (URL-safe Base64)\n"
        
        self.key_status_text.delete(1.0, tk.END)
        self.key_status_text.insert(1.0, status_text)
    
    def update_security_status(self):
        """Update security status display"""
        security_status = self.encryptor.get_security_status()
        
        status_text = f"""🛡️ SECURITY STATUS REPORT
{'=' * 40}

🔐 Authentication Status:
   • Password Set: {'✅ Yes' if security_status['has_password'] else '❌ No'}
   • Failed Attempts: {security_status['failed_attempts']}/{self.encryptor.max_failed_attempts}
   • Account Status: {'🔒 LOCKED' if security_status['is_locked_out'] else '✅ Active'}

🔑 Key Management:
   • Encryption Key: {'✅ Loaded' if security_status['has_key'] else '❌ Not Loaded'}
   • Key Creation: {security_status.get('creation_time', 'Unknown')[:19] if security_status.get('creation_time') else 'Not Set'}

📊 Operation Statistics:
   • Total Operations: {security_status['total_operations']}
   • Successful Ops: {security_status.get('successful_operations', 0)}

🔒 Security Recommendations:
"""
        
        # Add security recommendations
        if not security_status['has_password']:
            status_text += "   ⚠️ Set a strong master password\n"
        if security_status['failed_attempts'] > 0:
            status_text += "   ⚠️ Monitor failed login attempts\n"
        if security_status['total_operations'] == 0:
            status_text += "   💡 Test encryption with sample files\n"
        if security_status['has_password'] and security_status['has_key'] and security_status['failed_attempts'] == 0:
            status_text += "   ✅ Security configuration is optimal\n"
        
        self.security_text.delete(1.0, tk.END)
        self.security_text.insert(1.0, status_text)
    
    def update_system_info(self):
        """Update system information display"""
        import platform
        import sys
        import datetime
        
        system_info = f"""💻 SYSTEM INFORMATION
{'=' * 40}

🖥️ Operating System:
   • Platform: {platform.system()} {platform.release()}
   • Architecture: {platform.machine()}
   • Processor: {platform.processor() or 'Unknown'}

🐍 Python Environment:
   • Version: {sys.version.split()[0]}
   • Implementation: {platform.python_implementation()}
   • Compiler: {platform.python_compiler()}

📁 File System:
   • Current Directory: {os.getcwd()}
   • Total Files: {len([f for f in os.listdir('.') if os.path.isfile(f)])}
   • Encrypted Files: {len([f for f in os.listdir('.') if f.endswith('.encrypted')])}
   • Key Files: {len([f for f in os.listdir('.') if f.endswith('.key')])}

🕐 Session Information:
   • Current Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
   • Uptime: Session active
   • Memory: Available for operations

🔒 Cryptographic Libraries:
   • Cryptography: Available
   • Fernet: AES-128 CBC + HMAC-SHA256
   • Scrypt: PBKDF support enabled
"""
        
        self.system_info_text.delete(1.0, tk.END)
        self.system_info_text.insert(1.0, system_info)
    
    def log_message(self, message):
        """Add message to activity log with enhanced formatting"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Add to log
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Update status bar
        self.status_bar.config(text=f"🔐 {message}")
        
        # Auto-scroll log
        self.log_text.update_idletasks()
    
    def search_log(self, event=None):
        """Search through activity log"""
        search_term = self.log_search_var.get().lower()
        
        # Clear any existing highlights
        self.log_text.tag_remove('highlight', 1.0, tk.END)
        
        if not search_term:
            return
        
        # Search and highlight
        start = 1.0
        while True:
            pos = self.log_text.search(search_term, start, tk.END, nocase=True)
            if not pos:
                break
            
            end_pos = f"{pos}+{len(search_term)}c"
            self.log_text.tag_add('highlight', pos, end_pos)
            start = end_pos
        
        # Configure highlight style
        self.log_text.tag_config('highlight', background='yellow', foreground='black')
    
    def clear_log(self):
        """Clear activity log"""
        if messagebox.askyesno("Confirm", "Clear activity log?"):
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
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write("File Encryption Tool - Activity Log\n")
                    f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 50 + "\n\n")
                    f.write(self.log_text.get(1.0, tk.END))
                
                self.log_message(f"💾 Activity log saved: {filename}")
                messagebox.showinfo("Success", f"Activity log saved to:\n{filename}")
            except Exception as e:
                self.log_message(f"❌ Error saving log: {e}")
                messagebox.showerror("Error", f"Could not save log:\n{e}")
    
    def export_log(self):
        """Export log in various formats"""
        filename = filedialog.asksaveasfilename(
            title="Export Activity Log",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("JSON files", "*.json"), ("CSV files", "*.csv"), ("Text files", "*.txt")]
        )
        
        if filename:
            try:
                log_content = self.log_text.get(1.0, tk.END)
                
                if filename.endswith('.html'):
                    # Export as HTML
                    html_content = f"""<!DOCTYPE html>
<html><head><title>File Encryption Tool - Activity Log</title>
<style>body{{font-family:monospace;background:#f8f9fa;padding:20px;}}
.log{{background:white;padding:15px;border-radius:5px;box-shadow:0 2px 5px rgba(0,0,0,0.1);}}</style>
</head><body><h1>🔐 File Encryption Tool - Activity Log</h1>
<div class="log"><pre>{log_content}</pre></div></body></html>"""
                    
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                
                elif filename.endswith('.json'):
                    # Export as JSON
                    import json
                    log_entries = []
                    for line in log_content.strip().split('\n'):
                        if line.strip():
                            # Parse log entry
                            if line.startswith('[') and '] ' in line:
                                timestamp_end = line.index('] ')
                                timestamp = line[1:timestamp_end]
                                message = line[timestamp_end + 2:]
                                log_entries.append({"timestamp": timestamp, "message": message})
                    
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump({"log_entries": log_entries, "export_time": datetime.datetime.now().isoformat()}, f, indent=2)
                
                else:
                    # Export as plain text
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write("File Encryption Tool - Activity Log Export\n")
                        f.write(f"Exported: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                        f.write("=" * 50 + "\n\n")
                        f.write(log_content)
                
                self.log_message(f"📧 Activity log exported: {filename}")
                messagebox.showinfo("Success", f"Activity log exported to:\n{filename}")
                
            except Exception as e:
                self.log_message(f"❌ Error exporting log: {e}")
                messagebox.showerror("Error", f"Could not export log:\n{e}")
    
    def get_python_version(self):
        """Get Python version string"""
        import sys
        return f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

def main():
    """Main function to run the advanced GUI"""
    root = tk.Tk()
    
    # Set window icon if available
    try:
        root.iconbitmap('icon.ico')
    except:
        pass
    
    # Create application
    app = AdvancedFileEncryptionGUI(root)
    
    # Log startup messages
    app.log_message("🚀 Advanced File Encryption Tool started")
    app.log_message("🔐 Password-based authentication enabled")
    app.log_message("📋 Modern GUI interface loaded")
    app.log_message("🛡️ Security systems initialized")
    
    # Center window on screen
    try:
        root.eval('tk::PlaceWindow . center')
    except:
        # Fallback centering method
        root.update_idletasks()
        x = (root.winfo_screenwidth() // 2) - (root.winfo_width() // 2)
        y = (root.winfo_screenheight() // 2) - (root.winfo_height() // 2)
        root.geometry(f"+{x}+{y}")
    
    # Start the GUI event loop
    root.mainloop()

if __name__ == "__main__":
    import datetime  # Import needed for various functions
    main()
