# from flask import Flask, request, jsonify
# import base64
# import os
# import tempfile
# from encryption_module import FileEncryptor

# app = Flask(__name__)
# encryptor = FileEncryptor()

# def extract_text_from_file(file_path, filename, file_type):
#     """Extract text content from various file formats"""
#     try:
#         # Plain text files
#         if (file_type.startswith('text/') or 
#             filename.lower().endswith(('.txt', '.md', '.py', '.html', '.css', '.js', '.json', '.xml', '.csv'))):
#             with open(file_path, 'r', encoding='utf-8') as f:
#                 return f.read()
        
#         # Microsoft Word documents (.docx)
#         elif filename.lower().endswith('.docx') or 'wordprocessingml' in file_type:
#             try:
#                 import zipfile
#                 import xml.etree.ElementTree as ET
                
#                 # Word documents are ZIP files containing XML
#                 with zipfile.ZipFile(file_path, 'r') as docx:
#                     # Extract the main document XML
#                     content = docx.read('word/document.xml')
#                     root = ET.fromstring(content)
                    
#                     # Extract all text nodes
#                     text_content = []
#                     for elem in root.iter():
#                         if elem.text and elem.text.strip():
#                             text_content.append(elem.text.strip())
                    
#                     return '\n'.join(text_content) if text_content else None
#             except:
#                 pass
        
#         # PDF files (basic extraction)
#         elif filename.lower().endswith('.pdf') or file_type == 'application/pdf':
#             try:
#                 # Try basic PDF text extraction (requires no external libraries)
#                 with open(file_path, 'rb') as f:
#                     content = f.read().decode('latin-1', errors='ignore')
                    
#                     # Look for text between BT and ET markers (basic PDF text)
#                     import re
#                     text_matches = re.findall(r'BT(.*?)ET', content, re.DOTALL)
                    
#                     if text_matches:
#                         # Extract readable text from PDF commands
#                         extracted = []
#                         for match in text_matches:
#                             # Look for text in parentheses or brackets
#                             text_parts = re.findall(r'[\(\[]([^\)\]]+)[\)\]]', match)
#                             extracted.extend(text_parts)
                        
#                         return '\n'.join(extracted) if extracted else None
#             except:
#                 pass
        
#         # Try as UTF-8 text (fallback for unknown formats)
#         try:
#             with open(file_path, 'r', encoding='utf-8') as f:
#                 content = f.read()
#                 # Check if it's mostly readable text (at least 80% printable)
#                 printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
#                 if len(content) > 0 and (printable_chars / len(content)) > 0.8:
#                     return content
#         except:
#             pass
        
#         # Try as other encodings
#         for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
#             try:
#                 with open(file_path, 'r', encoding=encoding) as f:
#                     content = f.read()
#                     # Basic check for readable content
#                     if len([c for c in content if c.isprintable()]) > len(content) * 0.7:
#                         return content
#             except:
#                 continue
        
#         return None
        
#     except Exception as e:
#         print(f"Error extracting text: {e}")
#         return None

# @app.route('/')
# def home():
#     return '''
#     <!DOCTYPE html>
#     <html>
#     <head>
#         <title>File Encryption Tool </title>
#         <style>
#             body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
#             .header { background: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 10px; margin-bottom: 20px; }
#             .section { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
#             .btn { background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px; border: none; cursor: pointer; }
#             .btn-success { background: #27ae60; }
#             .btn-danger { background: #e74c3c; }
#             .btn:hover { opacity: 0.9; }
#             textarea { width: 100%; height: 120px; padding: 10px; border: 2px solid #ddd; border-radius: 5px; font-family: monospace; }
#             .result { margin: 15px 0; padding: 15px; border-radius: 5px; }
#             .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
#             .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
#             .demo-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
#             .card { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
#             .encrypted-text { background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; word-break: break-all; font-size: 12px; max-height: 100px; overflow-y: auto; border: 1px solid #dee2e6; }
#             .file-info { background: #e3f2fd; padding: 8px; border-radius: 4px; margin: 5px 0; font-size: 12px; }
#             input[type="file"] { padding: 8px; border: 2px dashed #007bff; border-radius: 5px; width: 100%; background: #f8f9fa; }
#             input[type="radio"] { margin-right: 5px; }
#             .content-display { max-height: 200px; overflow-y: auto; background: white; padding: 8px; border: 1px solid #ddd; border-radius: 3px; white-space: pre-wrap; }
#         </style>
#     </head>
#     <body>
#         <div class="header">
#             <h1>🔐 File Encryption Tool</h1>
#             <p>Operating Systems Project </p>
#         </div>
        
        
#         <div class="section">
#             <h2>🚀 Interactive Demo</h2>
#             <p><strong>Try the encryption tool right here in your browser!</strong></p>
            
#             <h3>Step 1: Generate Encryption Key</h3>
#             <button class="btn btn-success" onclick="generateKey()">🔑 Generate New Key</button>
#             <div id="keyResult"></div>
            
#             <h3>Step 2: Choose Input Method</h3>
#             <div style="margin-bottom: 15px;">
#                 <label style="margin-right: 20px;">
#                     <input type="radio" name="inputMethod" value="text" checked onchange="toggleInputMethod()"> 
#                     📝 Enter Text Manually
#                 </label>
#                 <label>
#                     <input type="radio" name="inputMethod" value="file" onchange="toggleInputMethod()"> 
#                     📁 Browse & Select File
#                 </label>
#             </div>

#             <div id="textInput">
#                 <textarea id="plainText" placeholder="Enter your text here to encrypt...">Hello! This is a test message for the file encryption tool.

# This tool demonstrates:
# - File system operations
# - Security mechanisms  
# - Cryptographic operations
# - User interface design

# Operating Systems Project - 2025</textarea>
#             </div>

#             <div id="fileInput" style="display: none;">
#                 <input type="file" id="fileSelector" accept="*/*" onchange="handleFileSelect()" style="margin-bottom: 10px;">
#                 <div id="filePreview" style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; display: none;">
#                     <strong>Selected File:</strong><br>
#                     <span id="fileName"></span><br>
#                     <span id="fileSize"></span><br><br>
#                     <strong>File Content Preview:</strong><br>
#                     <div id="fileContent" style="max-height: 100px; overflow-y: auto; background: white; padding: 8px; border: 1px solid #ddd; border-radius: 3px;"></div>
#                 </div>
#             </div>

#             <br>
#             <button class="btn" onclick="encryptContent()">🔒 Encrypt Content</button>
#             <div id="encryptResult"></div>
            
#             <h3>Step 3: Decrypt Content</h3>
#             <button class="btn btn-danger" onclick="decryptText()">🔓 Decrypt Content</button>
#             <div id="decryptResult"></div>
#         </div>

#         <footer style="background: #2c3e50; color: white; text-align: center; padding: 20px; border-radius: 10px; margin-top: 30px;">
#             <p>🔐 File Encryption Tool - Operating Systems Project 2025</p>
#             <p>Built with Python | Secured with AES-256 | Cross-platform Compatible</p>
#         </footer>

#         <script>
#             let currentKey = null;
#             let encryptedData = null;
#             let selectedFile = null;

#             function toggleInputMethod() {
#                 const method = document.querySelector('input[name="inputMethod"]:checked').value;
#                 const textInput = document.getElementById('textInput');
#                 const fileInput = document.getElementById('fileInput');
                
#                 if (method === 'text') {
#                     textInput.style.display = 'block';
#                     fileInput.style.display = 'none';
#                     selectedFile = null;
#                 } else {
#                     textInput.style.display = 'none';
#                     fileInput.style.display = 'block';
#                 }
#             }

#             function handleFileSelect() {
#                 const fileSelector = document.getElementById('fileSelector');
#                 const file = fileSelector.files[0];
                
#                 if (file) {
#                     selectedFile = file;
                    
#                     // Show file info
#                     document.getElementById('fileName').textContent = file.name;
#                     document.getElementById('fileSize').textContent = formatFileSize(file.size) + ' (' + (file.type || 'unknown type') + ')';
                    
#                     // Show preview for text files
#                     if (file.type.startsWith('text/') || file.name.endsWith('.txt') || file.name.endsWith('.md') || file.name.endsWith('.py') || file.name.endsWith('.html') || file.name.endsWith('.css') || file.name.endsWith('.js')) {
#                         const reader = new FileReader();
#                         reader.onload = function(e) {
#                             const content = e.target.result;
#                             document.getElementById('fileContent').textContent = content.length > 200 ? content.substring(0, 200) + '...' : content;
#                             document.getElementById('filePreview').style.display = 'block';
#                         };
#                         reader.readAsText(file);
#                     } else {
#                         document.getElementById('fileContent').innerHTML = '<em>[File selected - preview not available for this format]</em>';
#                         document.getElementById('filePreview').style.display = 'block';
#                     }
#                 }
#             }

#             function formatFileSize(bytes) {
#                 if (bytes === 0) return '0 Bytes';
#                 const k = 1024;
#                 const sizes = ['Bytes', 'KB', 'MB', 'GB'];
#                 const i = Math.floor(Math.log(bytes) / Math.log(k));
#                 return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
#             }

#             function generateKey() {
#                 fetch('/generate_key', { method: 'POST' })
#                     .then(response => response.json())
#                     .then(result => {
#                         const keyResultDiv = document.getElementById('keyResult');
#                         if (result.success) {
#                             currentKey = result.key;
#                             keyResultDiv.innerHTML = '<div class="result success"><strong>✅ ' + result.message + '</strong><br><small>🔒 Key generated and ready for encryption!</small></div>';
#                         } else {
#                             keyResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
#                         }
#                     })
#                     .catch(error => {
#                         document.getElementById('keyResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
#                     });
#             }

#             function encryptContent() {
#                 const method = document.querySelector('input[name="inputMethod"]:checked').value;
#                 let contentToEncrypt = '';
#                 let contentName = '';
                
#                 if (method === 'text') {
#                     contentToEncrypt = document.getElementById('plainText').value;
#                     contentName = 'Manual Text Input';
#                     if (!contentToEncrypt.trim()) {
#                         document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Please enter some text to encrypt!</div>';
#                         return;
#                     }
#                     performEncryption(contentToEncrypt, contentName, 'text/plain');
#                 } else {
#                     if (!selectedFile) {
#                         document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Please select a file to encrypt!</div>';
#                         return;
#                     }
                    
#                     const reader = new FileReader();
#                     reader.onload = function(e) {
#                         contentToEncrypt = e.target.result;
#                         contentName = selectedFile.name;
#                         performEncryption(contentToEncrypt, contentName, selectedFile.type || 'application/octet-stream');
#                     };
                    
#                     // Read file as base64 for binary files, text for text files
#                     if (selectedFile.type.startsWith('text/') || selectedFile.name.endsWith('.txt') || selectedFile.name.endsWith('.md') || selectedFile.name.endsWith('.py') || selectedFile.name.endsWith('.html') || selectedFile.name.endsWith('.css') || selectedFile.name.endsWith('.js')) {
#                         reader.readAsText(selectedFile);
#                     } else {
#                         reader.readAsDataURL(selectedFile); // This will be base64 encoded
#                     }
#                 }
#             }

#             function performEncryption(content, contentName, contentType) {
#                 fetch('/encrypt_content', {
#                     method: 'POST',
#                     headers: { 'Content-Type': 'application/json' },
#                     body: JSON.stringify({ 
#                         content: content,
#                         content_name: contentName,
#                         content_type: contentType
#                     })
#                 })
#                 .then(response => response.json())
#                 .then(result => {
#                     const encryptResultDiv = document.getElementById('encryptResult');
#                     if (result.success) {
#                         currentKey = result.key;
#                         encryptedData = result.encrypted_data;
#                         encryptResultDiv.innerHTML = '<div class="result success"><strong>✅ ' + result.message + '</strong><br><small>📁 Content: ' + contentName + '</small><div class="encrypted-text"><strong>Encrypted Data:</strong><br>' + result.encrypted_data + '</div><small>🔐 Content successfully encrypted with AES-256! Ready for decryption.</small></div>';
#                     } else {
#                         encryptResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
#                     }
#                 })
#                 .catch(error => {
#                     document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
#                 });
#             }

#             function decryptText() {
#                 if (!currentKey || !encryptedData) {
#                     document.getElementById('decryptResult').innerHTML = '<div class="result error">❌ Please encrypt some content first!</div>';
#                     return;
#                 }

#                 fetch('/decrypt_text', {
#                     method: 'POST',
#                     headers: { 'Content-Type': 'application/json' },
#                     body: JSON.stringify({ 
#                         encrypted_data: encryptedData, 
#                         key: currentKey,
#                         original_type: selectedFile ? selectedFile.type : 'text/plain',
#                         original_name: selectedFile ? selectedFile.name : 'Manual Text'
#                     })
#                 })
#                 .then(response => response.json())
#                 .then(result => {
#                     const decryptResultDiv = document.getElementById('decryptResult');
#                     if (result.success) {
#                         let displayContent = '';
                        
#                         if (result.is_binary) {
#                             displayContent = `<strong>📁 File Type:</strong> ${result.file_type}<br>
#                                             <strong>📊 File Size:</strong> ${result.file_size} bytes<br>
#                                             <strong>✅ Status:</strong> File decrypted successfully!<br>
#                                             <small>💡 This file format doesn't contain extractable text content.</small>`;
#                         } else {
#                             displayContent = `<strong>Extracted Text Content:</strong><br>`;
#                             if (result.file_info) {
#                                 displayContent += `<small>${result.file_info}</small><br>`;
#                             }
#                             displayContent += `<div class="content-display">${result.decrypted_text}</div>`;
#                         }
                        
#                         decryptResultDiv.innerHTML = `<div class="result success"><strong>✅ ${result.message}</strong><br>${displayContent}<small>🎉 Perfect! Content successfully decrypted and processed.</small></div>`;
#                     } else {
#                         decryptResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
#                     }
#                 })
#                 .catch(error => {
#                     document.getElementById('decryptResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
#                 });
#             }

#             // Auto-generate key on page load
#             window.onload = function() {
#                 setTimeout(generateKey, 1000);
#             };
#         </script>
#     </body>
#     </html>
#     '''

# @app.route('/generate_key', methods=['POST'])
# def generate_key():
#     try:
#         key = encryptor.generate_key()
#         key_b64 = base64.b64encode(key).decode('utf-8')
#         return jsonify({'success': True, 'message': 'New encryption key generated!', 'key': key_b64})
#     except Exception as e:
#         return jsonify({'success': False, 'message': str(e)})

# @app.route('/encrypt_content', methods=['POST'])
# def encrypt_content():
#     try:
#         data = request.json
#         content = data.get('content', '')
#         content_name = data.get('content_name', 'content')
#         content_type = data.get('content_type', 'text/plain')
        
#         if not content:
#             return jsonify({'success': False, 'message': 'No content provided'})
        
#         if encryptor.key is None:
#             encryptor.generate_key()
        
#         # Handle base64 data (for binary files)
#         if content.startswith('data:'):
#             # Extract the base64 part
#             content = content.split(',')[1]
#             import base64 as b64
#             content_bytes = b64.b64decode(content)
#         else:
#             # Regular text content
#             content_bytes = content.encode('utf-8')
        
#         # Create temporary file
#         with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as temp_file:
#             temp_file.write(content_bytes)
#             temp_filename = temp_file.name
        
#         # Encrypt the file
#         encrypted_filename = encryptor.encrypt_file(temp_filename)
        
#         # Read encrypted content
#         with open(encrypted_filename, 'rb') as f:
#             encrypted_data = f.read()
        
#         # Clean up
#         os.unlink(temp_filename)
#         os.unlink(encrypted_filename)
        
#         # Convert to base64
#         encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
#         key_b64 = base64.b64encode(encryptor.key).decode('utf-8')
        
#         return jsonify({
#             'success': True,
#             'encrypted_data': encrypted_b64,
#             'key': key_b64,
#             'message': f'Content "{content_name}" encrypted successfully!'
#         })
        
#     except Exception as e:
#         return jsonify({'success': False, 'message': str(e)})

# @app.route('/decrypt_text', methods=['POST'])
# def decrypt_text():
#     try:
#         data = request.json
#         encrypted_b64 = data.get('encrypted_data', '')
#         key_b64 = data.get('key', '')
#         original_type = data.get('original_type', 'text/plain')
#         original_name = data.get('original_name', 'content')
        
#         if not encrypted_b64 or not key_b64:
#             return jsonify({'success': False, 'message': 'Missing encrypted data or key'})
        
#         # Decode from base64
#         encrypted_data = base64.b64decode(encrypted_b64)
#         key = base64.b64decode(key_b64)
        
#         # Set the key
#         from cryptography.fernet import Fernet
#         encryptor.key = key
#         encryptor.fernet = Fernet(key)
        
#         # Create temporary encrypted file
#         with tempfile.NamedTemporaryFile(delete=False, suffix='.encrypted') as temp_file:
#             temp_file.write(encrypted_data)
#             temp_encrypted_filename = temp_file.name
        
#         # Decrypt the file
#         decrypted_filename = encryptor.decrypt_file(temp_encrypted_filename)
        
#         # Get file size
#         file_size = os.path.getsize(decrypted_filename)
        
#         # Try to extract text content from various file formats
#         extracted_text = extract_text_from_file(decrypted_filename, original_name, original_type)
        
#         # Clean up
#         os.unlink(temp_encrypted_filename)
#         os.unlink(decrypted_filename)
        
#         if extracted_text:
#             return jsonify({
#                 'success': True,
#                 'is_binary': False,
#                 'decrypted_text': extracted_text,
#                 'file_info': f"File: {original_name} ({original_type}) - {file_size} bytes",
#                 'message': f'Text extracted from "{original_name}" successfully!'
#             })
#         else:
#             return jsonify({
#                 'success': True,
#                 'is_binary': True,
#                 'file_type': original_type or 'Unknown',
#                 'file_size': file_size,
#                 'message': f'File "{original_name}" decrypted successfully (no text content extractable)'
#             })
        
#     except Exception as e:
#         return jsonify({'success': False, 'message': str(e)})

# if __name__ == '__main__':
#     app.run(debug=True, host='0.0.0.0', port=5000)

from flask import Flask, request, jsonify, render_template_string, session
import base64
import os
import tempfile
import time
import json
import uuid
from datetime import datetime
from encryption_module import AdvancedFileEncryptor

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production

# Initialize advanced encryptor
encryptor = AdvancedFileEncryptor()

# Global variables for batch processing
batch_queues = {}
active_batches = {}

def extract_text_from_file(file_path, filename, file_type):
    """Extract text content from various file formats - Enhanced version"""
    try:
        # Plain text files
        if (file_type.startswith('text/') or 
            filename.lower().endswith(('.txt', '.md', '.py', '.html', '.css', '.js', '.json', '.xml', '.csv'))):
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        # Microsoft Word documents (.docx)
        elif filename.lower().endswith('.docx') or 'wordprocessingml' in file_type:
            try:
                import zipfile
                import xml.etree.ElementTree as ET
                
                with zipfile.ZipFile(file_path, 'r') as docx:
                    content = docx.read('word/document.xml')
                    root = ET.fromstring(content)
                    
                    text_content = []
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            text_content.append(elem.text.strip())
                    
                    return '\n'.join(text_content) if text_content else None
            except:
                pass
        
        # PDF files (basic extraction)
        elif filename.lower().endswith('.pdf') or file_type == 'application/pdf':
            try:
                with open(file_path, 'rb') as f:
                    content = f.read().decode('latin-1', errors='ignore')
                    
                    import re
                    text_matches = re.findall(r'BT(.*?)ET', content, re.DOTALL)
                    
                    if text_matches:
                        extracted = []
                        for match in text_matches:
                            text_parts = re.findall(r'[\(\[]([^\)\]]+)[\)\]]', match)
                            extracted.extend(text_parts)
                        
                        return '\n'.join(extracted) if extracted else None
            except:
                pass
        
        # Try as UTF-8 text (fallback)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
                if len(content) > 0 and (printable_chars / len(content)) > 0.8:
                    return content
        except:
            pass
        
        return None
        
    except Exception as e:
        print(f"Error extracting text: {e}")
        return None

@app.route('/')
def home():
    """Enhanced home page with modern UI and advanced features"""
    return '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔐 Advanced File Encryption Tool - Password Protected</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --primary-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                --success-color: #10b981;
                --error-color: #ef4444;
                --warning-color: #f59e0b;
                --info-color: #3b82f6;
                --dark-bg: #1f2937;
                --card-bg: rgba(255, 255, 255, 0.1);
                --glass-bg: rgba(255, 255, 255, 0.05);
                --text-primary: #ffffff;
                --text-secondary: #d1d5db;
                --border-color: rgba(255, 255, 255, 0.1);
            }

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Inter', system-ui, -apple-system, sans-serif;
                background: var(--primary-gradient);
                color: var(--text-primary);
                min-height: 100vh;
                line-height: 1.6;
            }

            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
            }

            .header {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 30px;
                text-align: center;
                margin-bottom: 30px;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            }

            .header h1 {
                font-size: 2.5rem;
                font-weight: 700;
                margin-bottom: 10px;
                background: linear-gradient(45deg, #fff, #e0e7ff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .header p {
                font-size: 1.1rem;
                color: var(--text-secondary);
                font-weight: 500;
            }

            .features-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }

            .feature-card {
                background: var(--card-bg);
                backdrop-filter: blur(10px);
                border: 1px solid var(--border-color);
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                transition: all 0.3s ease;
                box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
            }

            .feature-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 25px 50px rgba(0, 0, 0, 0.2);
                border-color: rgba(255, 255, 255, 0.3);
            }

            .feature-icon {
                font-size: 2.5rem;
                margin-bottom: 15px;
                background: var(--primary-gradient);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .glass-card {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 30px;
                margin: 20px 0;
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
                transition: all 0.3s ease;
            }

            .glass-card:hover {
                border-color: rgba(255, 255, 255, 0.2);
                transform: translateY(-2px);
            }

            .tab-container {
                margin-bottom: 30px;
            }

            .tab-buttons {
                display: flex;
                background: var(--glass-bg);
                border-radius: 15px;
                padding: 5px;
                margin-bottom: 25px;
                border: 1px solid var(--border-color);
            }

            .tab-button {
                flex: 1;
                background: transparent;
                color: var(--text-secondary);
                border: none;
                padding: 15px 20px;
                border-radius: 10px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
                font-family: inherit;
            }

            .tab-button.active {
                background: var(--primary-gradient);
                color: white;
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
            }

            .tab-content {
                display: none;
                animation: fadeIn 0.3s ease;
            }

            .tab-content.active {
                display: block;
            }

            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }

            .form-group {
                margin-bottom: 20px;
            }

            .form-label {
                display: block;
                margin-bottom: 8px;
                font-weight: 600;
                color: var(--text-primary);
            }

            .form-input, .form-select, .form-textarea {
                width: 100%;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 15px 20px;
                color: var(--text-primary);
                font-size: 16px;
                transition: all 0.3s ease;
                font-family: inherit;
            }

            .form-input:focus, .form-select:focus, .form-textarea:focus {
                outline: none;
                border-color: rgba(102, 126, 234, 0.5);
                background: rgba(255, 255, 255, 0.08);
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }

            .form-textarea {
                min-height: 120px;
                resize: vertical;
                font-family: 'Courier New', monospace;
            }

            .password-container {
                position: relative;
            }

            .password-toggle {
                position: absolute;
                right: 15px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                color: var(--text-secondary);
                cursor: pointer;
                font-size: 18px;
                transition: color 0.3s ease;
            }

            .password-toggle:hover {
                color: var(--text-primary);
            }

            .strength-meter {
                margin-top: 10px;
                height: 4px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 2px;
                overflow: hidden;
            }

            .strength-bar {
                height: 100%;
                border-radius: 2px;
                transition: all 0.3s ease;
                width: 0%;
            }

            .strength-weak { background: var(--error-color); width: 25%; }
            .strength-medium { background: var(--warning-color); width: 50%; }
            .strength-strong { background: var(--info-color); width: 75%; }
            .strength-very-strong { background: var(--success-color); width: 100%; }

            .btn {
                background: var(--primary-gradient);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 15px 30px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
                font-family: inherit;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }

            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 15px 35px rgba(102, 126, 234, 0.4);
            }

            .btn:active {
                transform: translateY(0);
            }

            .btn-success {
                background: linear-gradient(45deg, var(--success-color), #059669);
            }

            .btn-danger {
                background: linear-gradient(45deg, var(--error-color), #dc2626);
            }

            .btn-warning {
                background: linear-gradient(45deg, var(--warning-color), #d97706);
            }

            .btn:disabled {
                opacity: 0.6;
                cursor: not-allowed;
                transform: none;
            }

            .result {
                margin: 20px 0;
                padding: 20px;
                border-radius: 12px;
                backdrop-filter: blur(10px);
                border-left: 4px solid transparent;
                animation: slideIn 0.3s ease;
            }

            @keyframes slideIn {
                from { opacity: 0; transform: translateX(-20px); }
                to { opacity: 1; transform: translateX(0); }
            }

            .result.success {
                background: rgba(16, 185, 129, 0.1);
                border-left-color: var(--success-color);
                border: 1px solid rgba(16, 185, 129, 0.2);
            }

            .result.error {
                background: rgba(239, 68, 68, 0.1);
                border-left-color: var(--error-color);
                border: 1px solid rgba(239, 68, 68, 0.2);
            }

            .result.warning {
                background: rgba(245, 158, 11, 0.1);
                border-left-color: var(--warning-color);
                border: 1px solid rgba(245, 158, 11, 0.2);
            }

            .encrypted-display {
                background: rgba(0, 0, 0, 0.2);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 15px;
                margin-top: 15px;
                font-family: 'Courier New', monospace;
                font-size: 12px;
                max-height: 150px;
                overflow-y: auto;
                word-break: break-all;
            }

            .file-upload {
                border: 2px dashed var(--border-color);
                border-radius: 12px;
                padding: 40px 20px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s ease;
                background: rgba(255, 255, 255, 0.02);
            }

            .file-upload:hover, .file-upload.dragover {
                border-color: rgba(102, 126, 234, 0.5);
                background: rgba(102, 126, 234, 0.05);
            }

            .file-upload-icon {
                font-size: 3rem;
                color: var(--text-secondary);
                margin-bottom: 15px;
            }

            .progress-container {
                margin: 20px 0;
            }

            .progress-bar {
                width: 100%;
                height: 8px;
                background: rgba(255, 255, 255, 0.1);
                border-radius: 4px;
                overflow: hidden;
            }

            .progress-fill {
                height: 100%;
                background: var(--primary-gradient);
                border-radius: 4px;
                transition: width 0.3s ease;
                width: 0%;
            }

            .batch-item {
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid var(--border-color);
                border-radius: 8px;
                padding: 15px;
                margin-bottom: 10px;
                display: flex;
                align-items: center;
                justify-content: space-between;
                transition: all 0.3s ease;
            }

            .batch-item:hover {
                background: rgba(255, 255, 255, 0.08);
                border-color: rgba(255, 255, 255, 0.2);
            }

            .batch-info {
                flex: 1;
            }

            .batch-status {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
            }

            .status-pending { background: rgba(156, 163, 175, 0.2); color: #9ca3af; }
            .status-processing { background: rgba(59, 130, 246, 0.2); color: #3b82f6; }
            .status-success { background: rgba(16, 185, 129, 0.2); color: #10b981; }
            .status-error { background: rgba(239, 68, 68, 0.2); color: #ef4444; }

            .footer {
                background: var(--glass-bg);
                backdrop-filter: blur(20px);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 30px;
                text-align: center;
                margin-top: 50px;
            }

            .footer-links {
                display: flex;
                justify-content: center;
                gap: 30px;
                margin-bottom: 20px;
            }

            .footer-link {
                color: var(--text-secondary);
                text-decoration: none;
                font-weight: 500;
                transition: color 0.3s ease;
            }

            .footer-link:hover {
                color: var(--text-primary);
            }

            @media (max-width: 768px) {
                .container {
                    padding: 15px;
                }
                
                .header h1 {
                    font-size: 2rem;
                }
                
                .features-grid {
                    grid-template-columns: 1fr;
                }
                
                .tab-buttons {
                    flex-direction: column;
                }
                
                .footer-links {
                    flex-direction: column;
                    gap: 15px;
                }
            }

            .loading {
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid rgba(255, 255, 255, 0.3);
                border-radius: 50%;
                border-top-color: white;
                animation: spin 1s ease-in-out infinite;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1000;
                max-width: 400px;
                animation: slideInRight 0.3s ease;
            }

            @keyframes slideInRight {
                from { opacity: 0; transform: translateX(100%); }
                to { opacity: 1; transform: translateX(0); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <header class="header">
                <h1><i class="fas fa-shield-alt"></i> Advanced File Encryption Tool</h1>
                <p>Password-Protected • AES-256 Encryption • Operating Systems Project</p>
            </header>

            <div class="features-grid">
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-key"></i></div>
                    <h3>Password Protection</h3>
                    <p>Secure password-based key derivation with Scrypt KDF</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-lock"></i></div>
                    <h3>AES-256 Encryption</h3>
                    <p>Industry-standard encryption with Fernet implementation</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-layer-group"></i></div>
                    <h3>Batch Processing</h3>
                    <p>Encrypt multiple files simultaneously with progress tracking</p>
                </div>
                <div class="feature-card">
                    <div class="feature-icon"><i class="fas fa-history"></i></div>
                    <h3>Operation History</h3>
                    <p>Complete audit trail with detailed analytics</p>
                </div>
            </div>

            <div class="glass-card">
                <div class="tab-container">
                    <div class="tab-buttons">
                        <button class="tab-button active" onclick="showTab('encryption')">
                            <i class="fas fa-lock"></i> Encryption
                        </button>
                        <button class="tab-button" onclick="showTab('batch')">
                            <i class="fas fa-layer-group"></i> Batch Processing
                        </button>
                        <button class="tab-button" onclick="showTab('history')">
                            <i class="fas fa-history"></i> History
                        </button>
                        <button class="tab-button" onclick="showTab('analytics')">
                            <i class="fas fa-chart-bar"></i> Analytics
                        </button>
                    </div>

                    <!-- Encryption Tab -->
                    <div id="encryption" class="tab-content active">
                        <h2><i class="fas fa-shield-alt"></i> File Encryption & Decryption</h2>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-key"></i> Master Password
                            </label>
                            <div class="password-container">
                                <input type="password" id="masterPassword" class="form-input" 
                                       placeholder="Enter your secure master password..."
                                       oninput="checkPasswordStrength()">
                                <button type="button" class="password-toggle" onclick="togglePasswordVisibility('masterPassword')">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                            <div class="strength-meter">
                                <div id="strengthBar" class="strength-bar"></div>
                            </div>
                            <div id="strengthText" class="form-label" style="margin-top: 5px; font-size: 14px; color: var(--text-secondary);"></div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-file-upload"></i> Select Files
                            </label>
                            <div class="file-upload" id="fileUpload" onclick="document.getElementById('fileInput').click()">
                                <div class="file-upload-icon">
                                    <i class="fas fa-cloud-upload-alt"></i>
                                </div>
                                <div>
                                    <strong>Click to select files</strong> or drag and drop here
                                </div>
                                <div style="color: var(--text-secondary); margin-top: 10px;">
                                    Supports all file types • Multiple files allowed
                                </div>
                            </div>
                            <input type="file" id="fileInput" multiple style="display: none;" onchange="handleFileSelection()">
                        </div>

                        <div id="selectedFiles" class="form-group" style="display: none;">
                            <label class="form-label">Selected Files</label>
                            <div id="fileList"></div>
                        </div>

                        <div class="form-group" style="display: flex; gap: 15px;">
                            <button class="btn btn-success" onclick="encryptFiles()">
                                <i class="fas fa-lock"></i> Encrypt Files
                            </button>
                            <button class="btn btn-danger" onclick="decryptFiles()">
                                <i class="fas fa-unlock"></i> Decrypt Files
                            </button>
                        </div>

                        <div id="encryptionResult"></div>
                    </div>

                    <!-- Batch Processing Tab -->
                    <div id="batch" class="tab-content">
                        <h2><i class="fas fa-layer-group"></i> Batch Processing</h2>
                        
                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-key"></i> Batch Password
                            </label>
                            <div class="password-container">
                                <input type="password" id="batchPassword" class="form-input" 
                                       placeholder="Password for batch encryption...">
                                <button type="button" class="password-toggle" onclick="togglePasswordVisibility('batchPassword')">
                                    <i class="fas fa-eye"></i>
                                </button>
                            </div>
                        </div>

                        <div class="form-group">
                            <label class="form-label">
                                <i class="fas fa-cog"></i> Batch Options
                            </label>
                            <div style="display: flex; gap: 20px; flex-wrap: wrap;">
                                <label style="display: flex; align-items: center; gap: 8px;">
                                    <input type="checkbox" id="deleteOriginal" style="scale: 1.2;">
                                    Delete original files after encryption
                                </label>
                                <label style="display: flex; align-items: center; gap: 8px;">
                                    <input type="checkbox" id="createReport" checked style="scale: 1.2;">
                                    Generate processing report
                                </label>
                            </div>
                        </div>

                        <div class="form-group">
                            <button class="btn" onclick="addToBatch()">
                                <i class="fas fa-plus"></i> Add Files to Batch
                            </button>
                            <button class="btn btn-warning" onclick="clearBatch()">
                                <i class="fas fa-trash"></i> Clear Batch
                            </button>
                        </div>

                        <div id="batchQueue" class="form-group">
                            <label class="form-label">Batch Queue (0 files)</label>
                            <div id="batchList"></div>
                        </div>

                        <div class="form-group">
                            <button class="btn btn-success" onclick="processBatch()" id="processBatchBtn" disabled>
                                <i class="fas fa-play"></i> Start Batch Processing
                            </button>
                        </div>

                        <div class="progress-container" id="batchProgress" style="display: none;">
                            <label class="form-label">Processing Progress</label>
                            <div class="progress-bar">
                                <div class="progress-fill" id="batchProgressBar"></div>
                            </div>
                            <div id="batchStatus" class="form-label" style="margin-top: 10px; color: var(--text-secondary);"></div>
                        </div>

                        <div id="batchResult"></div>
                    </div>

                    <!-- History Tab -->
                    <div id="history" class="tab-content">
                        <h2><i class="fas fa-history"></i> Operation History</h2>
                        
                        <div class="form-group" style="display: flex; gap: 15px; flex-wrap: wrap;">
                            <button class="btn" onclick="loadHistory()">
                                <i class="fas fa-sync"></i> Refresh History
                            </button>
                            <button class="btn btn-warning" onclick="exportHistory('csv')">
                                <i class="fas fa-download"></i> Export CSV
                            </button>
                            <button class="btn btn-warning" onclick="exportHistory('json')">
                                <i class="fas fa-download"></i> Export JSON
                            </button>
                            <button class="btn btn-danger" onclick="clearHistory()">
                                <i class="fas fa-trash"></i> Clear History
                            </button>
                        </div>

                        <div class="form-group">
                            <label class="form-label">Filter Operations</label>
                            <select id="historyFilter" class="form-select" onchange="loadHistory()">
                                <option value="all">All Operations</option>
                                <option value="encryption">Encryptions Only</option>
                                <option value="decryption">Decryptions Only</option>
                                <option value="batch">Batch Operations</option>
                            </select>
                        </div>

                        <div id="historyList" class="form-group">
                            <label class="form-label">Recent Operations</label>
                            <div id="historyContent">Click "Refresh History" to load operation history</div>
                        </div>
                    </div>

                    <!-- Analytics Tab -->
                    <div id="analytics" class="tab-content">
                        <h2><i class="fas fa-chart-bar"></i> Security Analytics</h2>
                        
                        <div class="form-group">
                            <button class="btn" onclick="loadAnalytics()">
                                <i class="fas fa-sync"></i> Refresh Analytics
                            </button>
                            <button class="btn btn-warning" onclick="generateReport()">
                                <i class="fas fa-file-alt"></i> Generate Report
                            </button>
                        </div>

                        <div id="analyticsContent" class="form-group">
                            <div class="features-grid">
                                <div class="feature-card">
                                    <div class="feature-icon"><i class="fas fa-shield-alt"></i></div>
                                    <h3>Total Operations</h3>
                                    <p id="totalOps">0</p>
                                </div>
                                <div class="feature-card">
                                    <div class="feature-icon"><i class="fas fa-check-circle"></i></div>
                                    <h3>Success Rate</h3>
                                    <p id="successRate">0%</p>
                                </div>
                                <div class="feature-card">
                                    <div class="feature-icon"><i class="fas fa-lock"></i></div>
                                    <h3>Files Encrypted</h3>
                                    <p id="filesEncrypted">0</p>
                                </div>
                                <div class="feature-card">
                                    <div class="feature-icon"><i class="fas fa-database"></i></div>
                                    <h3>Data Processed</h3>
                                    <p id="dataProcessed">0 MB</p>
                                </div>
                            </div>
                            
                            <div id="detailedAnalytics"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <footer class="footer">
            <div class="footer-links">
                <a href="#" class="footer-link">Documentation</a>
                <a href="#" class="footer-link">Security</a>
                <a href="#" class="footer-link">Support</a>
                <a href="#" class="footer-link">GitHub</a>
            </div>
            <div style="color: var(--text-secondary);">
                <strong>🔐 Advanced File Encryption Tool</strong><br>
                Operating Systems Project • AES-256 • Password Protected<br>
                Built with Flask & Python • Cross-platform Compatible
            </div>
        </footer>

        <script>
            // Global variables
            let selectedFiles = [];
            let batchFiles = [];
            let currentBatchId = null;
            let masterPassword = '';

            // Tab management
            function showTab(tabName) {
                // Hide all tabs
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                // Remove active class from all buttons
                document.querySelectorAll('.tab-button').forEach(btn => {
                    btn.classList.remove('active');
                });
                
                // Show selected tab
                document.getElementById(tabName).classList.add('active');
                event.target.classList.add('active');
            }

            // Password strength checker
            function checkPasswordStrength() {
                const password = document.getElementById('masterPassword').value;
                const strengthBar = document.getElementById('strengthBar');
                const strengthText = document.getElementById('strengthText');
                
                let score = 0;
                let feedback = [];

                if (password.length >= 12) score += 2;
                else if (password.length >= 8) score += 1;
                else feedback.push('Use at least 8 characters');

                if (/[A-Z]/.test(password)) score += 1;
                else feedback.push('Add uppercase letters');

                if (/[a-z]/.test(password)) score += 1;
                else feedback.push('Add lowercase letters');

                if (/[0-9]/.test(password)) score += 1;
                else feedback.push('Add numbers');

                if (/[^A-Za-z0-9]/.test(password)) score += 1;
                else feedback.push('Add special characters');

                // Update strength display
                strengthBar.className = 'strength-bar';
                if (score >= 6) {
                    strengthBar.classList.add('strength-very-strong');
                    strengthText.innerHTML = '<i class="fas fa-check-circle" style="color: var(--success-color);"></i> Very Strong Password';
                    strengthText.style.color = 'var(--success-color)';
                } else if (score >= 4) {
                    strengthBar.classList.add('strength-strong');
                    strengthText.innerHTML = '<i class="fas fa-shield-alt" style="color: var(--info-color);"></i> Strong Password';
                    strengthText.style.color = 'var(--info-color)';
                } else if (score >= 2) {
                    strengthBar.classList.add('strength-medium');
                    strengthText.innerHTML = '<i class="fas fa-exclamation-triangle" style="color: var(--warning-color);"></i> Medium Password';
                    strengthText.style.color = 'var(--warning-color)';
                } else {
                    strengthBar.classList.add('strength-weak');
                    strengthText.innerHTML = '<i class="fas fa-times-circle" style="color: var(--error-color);"></i> Weak Password';
                    strengthText.style.color = 'var(--error-color)';
                }

                if (feedback.length > 0 && score < 4) {
                    strengthText.innerHTML += '<br><small>Suggestions: ' + feedback.slice(0, 3).join(', ') + '</small>';
                }

                masterPassword = password;
            }

            // Toggle password visibility
            function togglePasswordVisibility(inputId) {
                const input = document.getElementById(inputId);
                const icon = input.nextElementSibling.querySelector('i');
                
                if (input.type === 'password') {
                    input.type = 'text';
                    icon.className = 'fas fa-eye-slash';
                } else {
                    input.type = 'password';
                    icon.className = 'fas fa-eye';
                }
            }

            // File handling
            function handleFileSelection() {
                const fileInput = document.getElementById('fileInput');
                selectedFiles = Array.from(fileInput.files);
                updateFileDisplay();
            }

            function updateFileDisplay() {
                const selectedFilesDiv = document.getElementById('selectedFiles');
                const fileListDiv = document.getElementById('fileList');
                
                if (selectedFiles.length > 0) {
                    selectedFilesDiv.style.display = 'block';
                    fileListDiv.innerHTML = selectedFiles.map((file, index) => `
                        <div class="batch-item">
                            <div class="batch-info">
                                <strong>${file.name}</strong>
                                <div style="color: var(--text-secondary); font-size: 14px;">
                                    ${formatFileSize(file.size)} • ${file.type || 'Unknown type'}
                                </div>
                            </div>
                            <button class="btn btn-danger" style="padding: 8px 12px;" onclick="removeFile(${index})">
                                <i class="fas fa-times"></i>
                            </button>
                        </div>
                    `).join('');
                } else {
                    selectedFilesDiv.style.display = 'none';
                }
            }

            function removeFile(index) {
                selectedFiles.splice(index, 1);
                updateFileDisplay();
            }

            function formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            // Drag and drop
            document.getElementById('fileUpload').addEventListener('dragover', function(e) {
                e.preventDefault();
                this.classList.add('dragover');
            });

            document.getElementById('fileUpload').addEventListener('dragleave', function(e) {
                e.preventDefault();
                this.classList.remove('dragover');
            });

            document.getElementById('fileUpload').addEventListener('drop', function(e) {
                e.preventDefault();
                this.classList.remove('dragover');
                
                const files = Array.from(e.dataTransfer.files);
                selectedFiles = [...selectedFiles, ...files];
                updateFileDisplay();
            });

            // Encryption functions
            function encryptFiles() {
                if (selectedFiles.length === 0) {
                    showResult('encryptionResult', 'error', 'Please select files to encrypt!');
                    return;
                }

                if (!masterPassword) {
                    showResult('encryptionResult', 'error', 'Please enter a master password!');
                    return;
                }

                showResult('encryptionResult', 'info', '<div class="loading"></div> Encrypting files...');

                // Process files one by one
                processFilesSequentially(selectedFiles, 'encrypt', masterPassword)
                    .then(results => {
                        const successful = results.filter(r => r.success).length;
                        const total = results.length;
                        
                        let resultHtml = `<h3><i class="fas fa-check-circle"></i> Encryption Complete</h3>`;
                        resultHtml += `<p>Successfully encrypted ${successful}/${total} files</p>`;
                        
                        results.forEach(result => {
                            if (result.success) {
                                resultHtml += `<div class="batch-item">
                                    <div class="batch-info">
                                        <strong>${result.filename}</strong>
                                        <div style="color: var(--text-secondary); font-size: 14px;">
                                            Encrypted successfully • Password protected
                                        </div>
                                    </div>
                                    <span class="batch-status status-success">Success</span>
                                </div>`;
                            } else {
                                resultHtml += `<div class="batch-item">
                                    <div class="batch-info">
                                        <strong>${result.filename}</strong>
                                        <div style="color: var(--error-color); font-size: 14px;">
                                            ${result.error}
                                        </div>
                                    </div>
                                    <span class="batch-status status-error">Failed</span>
                                </div>`;
                            }
                        });

                        showResult('encryptionResult', successful === total ? 'success' : 'warning', resultHtml);
                        
                        // Clear files after successful encryption
                        if (successful > 0) {
                            selectedFiles = [];
                            updateFileDisplay();
                        }
                    })
                    .catch(error => {
                        showResult('encryptionResult', 'error', `Encryption failed: ${error.message}`);
                    });
            }

            function decryptFiles() {
                if (selectedFiles.length === 0) {
                    showResult('encryptionResult', 'error', 'Please select encrypted files to decrypt!');
                    return;
                }

                if (!masterPassword) {
                    showResult('encryptionResult', 'error', 'Please enter the correct password!');
                    return;
                }

                showResult('encryptionResult', 'info', '<div class="loading"></div> Decrypting files...');

                processFilesSequentially(selectedFiles, 'decrypt', masterPassword)
                    .then(results => {
                        const successful = results.filter(r => r.success).length;
                        const total = results.length;
                        
                        let resultHtml = `<h3><i class="fas fa-unlock"></i> Decryption Complete</h3>`;
                        resultHtml += `<p>Successfully decrypted ${successful}/${total} files</p>`;
                        
                        results.forEach(result => {
                            if (result.success) {
                                resultHtml += `<div class="batch-item">
                                    <div class="batch-info">
                                        <strong>${result.filename}</strong>
                                        <div style="color: var(--text-secondary); font-size: 14px;">
                                            Decrypted successfully
                                        </div>
                                    </div>
                                    <span class="batch-status status-success">Success</span>
                                </div>`;
                            } else {
                                resultHtml += `<div class="batch-item">
                                    <div class="batch-info">
                                        <strong>${result.filename}</strong>
                                        <div style="color: var(--error-color); font-size: 14px;">
                                            ${result.error}
                                        </div>
                                    </div>
                                    <span class="batch-status status-error">Failed</span>
                                </div>`;
                            }
                        });

                        showResult('encryptionResult', successful === total ? 'success' : 'warning', resultHtml);
                        
                        // Clear files after successful decryption
                        if (successful > 0) {
                            selectedFiles = [];
                            updateFileDisplay();
                        }
                    })
                    .catch(error => {
                        showResult('encryptionResult', 'error', `Decryption failed: ${error.message}`);
                    });
            }

            async function processFilesSequentially(files, operation, password) {
                const results = [];
                
                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    
                    try {
                        const formData = new FormData();
                        formData.append('file', file);
                        formData.append('password', password);
                        formData.append('operation', operation);
                        
                        const response = await fetch('/process_file', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const result = await response.json();
                        
                        results.push({
                            filename: file.name,
                            success: result.success,
                            error: result.message
                        });
                        
                    } catch (error) {
                        results.push({
                            filename: file.name,
                            success: false,
                            error: error.message
                        });
                    }
                }
                
                return results;
            }

            // Batch processing
            function addToBatch() {
                if (selectedFiles.length === 0) {
                    showNotification('error', 'Please select files to add to batch!');
                    return;
                }

                batchFiles = [...batchFiles, ...selectedFiles];
                selectedFiles = [];
                updateFileDisplay();
                updateBatchDisplay();
                
                showNotification('success', `Added ${selectedFiles.length} files to batch queue`);
            }

            function clearBatch() {
                batchFiles = [];
                updateBatchDisplay();
                showNotification('info', 'Batch queue cleared');
            }

            function updateBatchDisplay() {
                const batchQueue = document.getElementById('batchQueue');
                const batchList = document.getElementById('batchList');
                const processBatchBtn = document.getElementById('processBatchBtn');
                
                batchQueue.querySelector('.form-label').textContent = `Batch Queue (${batchFiles.length} files)`;
                
                if (batchFiles.length > 0) {
                    batchList.innerHTML = batchFiles.map((file, index) => `
                        <div class="batch-item">
                            <div class="batch-info">
                                <strong>${file.name}</strong>
                                <div style="color: var(--text-secondary); font-size: 14px;">
                                    ${formatFileSize(file.size)} • ${file.type || 'Unknown type'}
                                </div>
                            </div>
                            <div>
                                <span class="batch-status status-pending">Pending</span>
                                <button class="btn btn-danger" style="padding: 8px 12px; margin-left: 10px;" onclick="removeFromBatch(${index})">
                                    <i class="fas fa-times"></i>
                                </button>
                            </div>
                        </div>
                    `).join('');
                    
                    processBatchBtn.disabled = false;
                } else {
                    batchList.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 20px;">No files in batch queue</div>';
                    processBatchBtn.disabled = true;
                }
            }

            function removeFromBatch(index) {
                batchFiles.splice(index, 1);
                updateBatchDisplay();
            }

            function processBatch() {
                const password = document.getElementById('batchPassword').value;
                
                if (!password) {
                    showResult('batchResult', 'error', 'Please enter a password for batch processing!');
                    return;
                }

                if (batchFiles.length === 0) {
                    showResult('batchResult', 'error', 'No files in batch queue!');
                    return;
                }

                // Show progress
                document.getElementById('batchProgress').style.display = 'block';
                document.getElementById('processBatchBtn').disabled = true;
                
                // Start batch processing
                processBatchFiles(batchFiles, password);
            }

            async function processBatchFiles(files, password) {
                const totalFiles = files.length;
                let processed = 0;
                let successful = 0;
                const results = [];

                for (let i = 0; i < files.length; i++) {
                    const file = files[i];
                    
                    // Update progress
                    const progress = Math.round((processed / totalFiles) * 100);
                    document.getElementById('batchProgressBar').style.width = progress + '%';
                    document.getElementById('batchStatus').textContent = `Processing ${file.name} (${processed + 1}/${totalFiles})`;
                    
                    try {
                        const formData = new FormData();
                        formData.append('file', file);
                        formData.append('password', password);
                        formData.append('operation', 'encrypt');
                        
                        const response = await fetch('/process_file', {
                            method: 'POST',
                            body: formData
                        });
                        
                        const result = await response.json();
                        
                        if (result.success) {
                            successful++;
                        }
                        
                        results.push({
                            filename: file.name,
                            success: result.success,
                            error: result.message
                        });
                        
                    } catch (error) {
                        results.push({
                            filename: file.name,
                            success: false,
                            error: error.message
                        });
                    }
                    
                    processed++;
                }

                // Complete
                document.getElementById('batchProgressBar').style.width = '100%';
                document.getElementById('batchStatus').textContent = `Batch processing complete: ${successful}/${totalFiles} successful`;
                
                // Show results
                let resultHtml = `<h3><i class="fas fa-layer-group"></i> Batch Processing Complete</h3>`;
                resultHtml += `<p>Successfully processed ${successful}/${totalFiles} files</p>`;
                
                results.forEach(result => {
                    const statusClass = result.success ? 'status-success' : 'status-error';
                    const statusText = result.success ? 'Success' : 'Failed';
                    const icon = result.success ? 'check-circle' : 'times-circle';
                    
                    resultHtml += `<div class="batch-item">
                        <div class="batch-info">
                            <strong>${result.filename}</strong>
                            ${result.error && !result.success ? `<div style="color: var(--error-color); font-size: 14px;">${result.error}</div>` : ''}
                        </div>
                        <span class="batch-status ${statusClass}">
                            <i class="fas fa-${icon}"></i> ${statusText}
                        </span>
                    </div>`;
                });

                showResult('batchResult', successful === totalFiles ? 'success' : 'warning', resultHtml);
                
                // Reset
                setTimeout(() => {
                    document.getElementById('processBatchBtn').disabled = false;
                    if (successful > 0) {
                        batchFiles = batchFiles.filter((_, index) => !results[index].success);
                        updateBatchDisplay();
                    }
                }, 2000);
            }

            // History functions
            function loadHistory() {
                const filter = document.getElementById('historyFilter').value;
                
                fetch(`/history/get?type=${filter}&limit=50`)
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            displayHistory(data.history);
                        } else {
                            showResult('historyContent', 'error', 'Failed to load history');
                        }
                    })
                    .catch(error => {
                        console.error('Error loading history:', error);
                        document.getElementById('historyContent').innerHTML = '<div style="color: var(--error-color);">Error loading history</div>';
                    });
            }

            function displayHistory(history) {
                const historyContent = document.getElementById('historyContent');
                
                if (history.length === 0) {
                    historyContent.innerHTML = '<div style="text-align: center; color: var(--text-secondary); padding: 20px;">No operations found</div>';
                    return;
                }

                let historyHtml = '';
                history.forEach(operation => {
                    const timestamp = new Date(operation.timestamp).toLocaleString();
                    const statusClass = operation.success ? 'status-success' : 'status-error';
                    const statusText = operation.success ? 'Success' : 'Failed';
                    const icon = operation.operation_type === 'encryption' ? 'lock' : 'unlock';
                    
                    historyHtml += `<div class="batch-item">
                        <div class="batch-info">
                            <strong><i class="fas fa-${icon}"></i> ${operation.original_file}</strong>
                            <div style="color: var(--text-secondary); font-size: 14px;">
                                ${timestamp} • ${operation.operation_type} • ${formatFileSize(operation.file_size || 0)}
                                ${operation.password_protected ? ' • Password Protected' : ''}
                            </div>
                            ${operation.error_message ? `<div style="color: var(--error-color); font-size: 12px;">${operation.error_message}</div>` : ''}
                        </div>
                        <span class="batch-status ${statusClass}">${statusText}</span>
                    </div>`;
                });

                historyContent.innerHTML = historyHtml;
            }

            function exportHistory(format) {
                const filter = document.getElementById('historyFilter').value;
                
                fetch(`/history/export?format=${format}&type=${filter}`)
                    .then(response => response.blob())
                    .then(blob => {
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `encryption_history.${format}`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                        
                        showNotification('success', `History exported as ${format.toUpperCase()}`);
                    })
                    .catch(error => {
                        showNotification('error', 'Failed to export history');
                        console.error('Export error:', error);
                    });
            }

            function clearHistory() {
                if (confirm('Are you sure you want to clear all operation history? This cannot be undone.')) {
                    fetch('/history/clear', {method: 'POST'})
                        .then(response => response.json())
                        .then(data => {
                            if (data.success) {
                                showNotification('success', 'History cleared successfully');
                                loadHistory();
                            } else {
                                showNotification('error', 'Failed to clear history');
                            }
                        })
                        .catch(error => {
                            showNotification('error', 'Error clearing history');
                            console.error('Clear history error:', error);
                        });
                }
            }

            // Analytics functions
            function loadAnalytics() {
                fetch('/history/statistics')
                    .then(response => response.json())
                    .then(data => {
                        if (data.success) {
                            displayAnalytics(data.statistics);
                        } else {
                            showNotification('error', 'Failed to load analytics');
                        }
                    })
                    .catch(error => {
                        showNotification('error', 'Error loading analytics');
                        console.error('Analytics error:', error);
                    });
            }

            function displayAnalytics(stats) {
                document.getElementById('totalOps').textContent = stats.total_operations || 0;
                document.getElementById('successRate').textContent = (stats.success_rate || 0).toFixed(1) + '%';
                document.getElementById('filesEncrypted').textContent = stats.total_encryptions || 0;
                document.getElementById('dataProcessed').textContent = formatFileSize(stats.total_processed_size || 0);

                // Detailed analytics
                const detailedDiv = document.getElementById('detailedAnalytics');
                detailedDiv.innerHTML = `
                    <div class="glass-card">
                        <h3><i class="fas fa-chart-line"></i> Detailed Statistics</h3>
                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-top: 20px;">
                            <div>
                                <strong>Operations Breakdown</strong>
                                <div style="margin-top: 10px;">
                                    <div>Encryptions: ${stats.total_encryptions || 0}</div>
                                    <div>Decryptions: ${stats.total_decryptions || 0}</div>
                                    <div>Batch Operations: ${stats.total_batches || 0}</div>
                                    <div>Failed Operations: ${stats.failed_operations || 0}</div>
                                </div>
                            </div>
                            <div>
                                <strong>Performance Metrics</strong>
                                <div style="margin-top: 10px;">
                                    <div>Success Rate: ${(stats.success_rate || 0).toFixed(1)}%</div>
                                    <div>Total Data: ${formatFileSize(stats.total_processed_size || 0)}</div>
                                    <div>Avg File Size: ${formatFileSize((stats.total_processed_size || 0) / (stats.successful_operations || 1))}</div>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }

            function generateReport() {
                fetch('/analytics/report')
                    .then(response => response.blob())
                    .then(blob => {
                        const url = window.URL.createObjectURL(blob);
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = `encryption_analytics_report_${new Date().toISOString().split('T')[0]}.html`;
                        document.body.appendChild(a);
                        a.click();
                        document.body.removeChild(a);
                        window.URL.revokeObjectURL(url);
                        
                        showNotification('success', 'Analytics report generated and downloaded');
                    })
                    .catch(error => {
                        showNotification('error', 'Failed to generate report');
                        console.error('Report error:', error);
                    });
            }

            // Utility functions
            function showResult(containerId, type, message) {
                const container = document.getElementById(containerId);
                container.innerHTML = `<div class="result ${type}">${message}</div>`;
                container.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
            }

            function showNotification(type, message) {
                const notification = document.createElement('div');
                notification.className = `notification result ${type}`;
                notification.innerHTML = `
                    <div style="display: flex; align-items: center; justify-content: space-between;">
                        <span>${message}</span>
                        <button onclick="this.parentElement.parentElement.remove()" style="background: none; border: none; color: inherit; cursor: pointer; font-size: 18px;">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                `;
                
                document.body.appendChild(notification);
                
                // Auto-remove after 5 seconds
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 5000);
            }

            // Initialize
            document.addEventListener('DOMContentLoaded', function() {
                showNotification('info', 'Welcome to Advanced File Encryption Tool!');
                
                // Load initial data
                setTimeout(() => {
                    loadAnalytics();
                }, 1000);
            });
        </script>
    </body>
    </html>
    '''

# Enhanced API endpoints

@app.route('/process_file', methods=['POST'])
def process_file():
    """Enhanced file processing endpoint with password authentication"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'})
        
        file = request.files['file']
        password = request.form.get('password', '')
        operation = request.form.get('operation', 'encrypt')
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'})
        
        if not password:
            return jsonify({'success': False, 'message': 'Password required'})
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='_temp') as temp_file:
            file.save(temp_file.name)
            temp_filename = temp_file.name
        
        try:
            if operation == 'encrypt':
                # Encrypt file with password
                result = encryptor.encrypt_file(temp_filename, password)
                if result:
                    return jsonify({
                        'success': True,
                        'message': f'File "{file.filename}" encrypted successfully',
                        'operation': 'encryption',
                        'password_protected': True
                    })
                else:
                    return jsonify({'success': False, 'message': 'Encryption failed'})
            
            elif operation == 'decrypt':
                # Decrypt file with password
                result = encryptor.decrypt_file(temp_filename, password)
                if result:
                    return jsonify({
                        'success': True,
                        'message': f'File "{file.filename}" decrypted successfully',
                        'operation': 'decryption',
                        'password_protected': True
                    })
                else:
                    return jsonify({'success': False, 'message': 'Decryption failed - check password'})
            
            else:
                return jsonify({'success': False, 'message': 'Invalid operation'})
                
        finally:
            # Cleanup
            try:
                os.unlink(temp_filename)
            except:
                pass
            
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/batch/create', methods=['POST'])
def create_batch():
    """Create new batch processing queue"""
    try:
        batch_id = str(uuid.uuid4())
        batch_queues[batch_id] = {
            'id': batch_id,
            'files': [],
            'created_at': datetime.now().isoformat(),
            'status': 'created'
        }
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'message': 'Batch queue created successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/batch/add_files', methods=['POST'])
def add_batch_files():
    """Add files to batch processing queue"""
    try:
        data = request.json
        batch_id = data.get('batch_id')
        file_data_list = data.get('files', [])
        
        if batch_id not in batch_queues:
            return jsonify({'success': False, 'message': 'Invalid batch ID'})
        
        for file_data in file_data_list:
            batch_queues[batch_id]['files'].append({
                'name': file_data.get('name'),
                'size': file_data.get('size'),
                'type': file_data.get('type'),
                'status': 'pending',
                'added_at': datetime.now().isoformat()
            })
        
        return jsonify({
            'success': True,
            'message': f'Added {len(file_data_list)} files to batch queue',
            'total_files': len(batch_queues[batch_id]['files'])
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/batch/process', methods=['POST'])
def process_batch():
    """Process batch encryption"""
    try:
        data = request.json
        batch_id = data.get('batch_id')
        password = data.get('password')
        options = data.get('options', {})
        
        if batch_id not in batch_queues:
            return jsonify({'success': False, 'message': 'Invalid batch ID'})
        
        if not password:
            return jsonify({'success': False, 'message': 'Password required for batch processing'})
        
        batch = batch_queues[batch_id]
        batch['status'] = 'processing'
        batch['started_at'] = datetime.now().isoformat()
        
        # Store in active batches for progress tracking
        active_batches[batch_id] = {
            'total_files': len(batch['files']),
            'processed_files': 0,
            'successful_files': 0,
            'failed_files': 0,
            'current_file': None,
            'status': 'processing'
        }
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'message': 'Batch processing started',
            'status': 'processing'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/batch/status/<batch_id>')
def batch_status(batch_id):
    """Get batch processing status"""
    try:
        if batch_id not in active_batches:
            return jsonify({'success': False, 'message': 'Batch not found'})
        
        status = active_batches[batch_id]
        
        return jsonify({
            'success': True,
            'batch_id': batch_id,
            'status': status
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/history/get')
def get_file_history():
    """Get file operation history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        operation_type = request.args.get('type', 'all')
        
        if operation_type == 'all':
            operation_type = None
        
        history = encryptor.history_manager.get_history(limit, operation_type)
        
        return jsonify({
            'success': True,
            'history': history,
            'total_records': len(history)
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/history/statistics')
def get_history_statistics():
    """Get operation statistics"""
    try:
        stats = encryptor.history_manager.get_statistics()
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/history/export')
def export_history():
    """Export history in various formats"""
    try:
        format_type = request.args.get('format', 'csv').lower()
        operation_type = request.args.get('type', 'all')
        
        if operation_type == 'all':
            operation_type = None
        
        # Create temporary file for export
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=f'.{format_type}') as temp_file:
            temp_filename = temp_file.name
        
        encryptor.history_manager.export_history(temp_filename, format_type)
        
        # Read and return file
        with open(temp_filename, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Cleanup
        os.unlink(temp_filename)
        
        if format_type == 'csv':
            mimetype = 'text/csv'
        elif format_type == 'json':
            mimetype = 'application/json'
        else:
            mimetype = 'text/plain'
        
        from flask import Response
        return Response(
            content,
            mimetype=mimetype,
            headers={"Content-disposition": f"attachment; filename=encryption_history.{format_type}"}
        )
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/history/clear', methods=['POST'])
def clear_history():
    """Clear operation history"""
    try:
        encryptor.history_manager.clear_history()
        
        return jsonify({
            'success': True,
            'message': 'History cleared successfully'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/analytics/report')
def generate_analytics_report():
    """Generate comprehensive analytics report"""
    try:
        stats = encryptor.history_manager.get_statistics()
        history = encryptor.history_manager.get_history(limit=1000)
        
        # Generate HTML report
        report_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Encryption Analytics Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
                .header {{ background: #2c3e50; color: white; padding: 20px; border-radius: 8px; text-align: center; }}
                .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
                .stat-card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .history {{ background: white; padding: 20px; border-radius: 8px; margin-top: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔐 File Encryption Analytics Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="stats">
                <div class="stat-card">
                    <h3>Total Operations</h3>
                    <h2>{stats.get('total_operations', 0)}</h2>
                </div>
                <div class="stat-card">
                    <h3>Success Rate</h3>
                    <h2>{stats.get('success_rate', 0):.1f}%</h2>
                </div>
                <div class="stat-card">
                    <h3>Files Encrypted</h3>
                    <h2>{stats.get('total_encryptions', 0)}</h2>
                </div>
                <div class="stat-card">
                    <h3>Files Decrypted</h3>
                    <h2>{stats.get('total_decryptions', 0)}</h2>
                </div>
                <div class="stat-card">
                    <h3>Data Processed</h3>
                    <h2>{stats.get('total_processed_size', 0) / 1024 / 1024:.1f} MB</h2>
                </div>
                <div class="stat-card">
                    <h3>Batch Operations</h3>
                    <h2>{stats.get('total_batches', 0)}</h2>
                </div>
            </div>
            
            <div class="history">
                <h2>Recent Operations</h2>
                <table>
                    <tr>
                        <th>Timestamp</th>
                        <th>Operation</th>
                        <th>File</th>
                        <th>Size</th>
                        <th>Status</th>
                        <th>Protected</th>
                    </tr>
        """
        
        for op in history[:50]:  # Show last 50 operations
            size_mb = (op.get('file_size', 0) or 0) / 1024 / 1024
            status = 'Success' if op.get('success') else 'Failed'
            protected = 'Yes' if op.get('password_protected') else 'No'
            
            report_html += f"""
                    <tr>
                        <td>{op.get('timestamp', '')[:19]}</td>
                        <td>{op.get('operation_type', '').title()}</td>
                        <td>{op.get('original_file', '')}</td>
                        <td>{size_mb:.2f} MB</td>
                        <td>{status}</td>
                        <td>{protected}</td>
                    </tr>
            """
        
        report_html += """
                </table>
            </div>
        </body>
        </html>
        """
        
        from flask import Response
        return Response(
            report_html,
            mimetype='text/html',
            headers={"Content-disposition": "attachment; filename=encryption_analytics_report.html"}
        )
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
