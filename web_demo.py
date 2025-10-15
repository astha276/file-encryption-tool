from flask import Flask, render_template_string, request, jsonify
import base64
import os
import tempfile
from encryption_module import FileEncryptor

app = Flask(__name__)
encryptor = FileEncryptor()

def extract_text_from_file(file_path, filename, file_type):
    """Extract text content from various file formats"""
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
                
                # Word documents are ZIP files containing XML
                with zipfile.ZipFile(file_path, 'r') as docx:
                    # Extract the main document XML
                    content = docx.read('word/document.xml')
                    root = ET.fromstring(content)
                    
                    # Extract all text nodes
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
                # Try basic PDF text extraction (requires no external libraries)
                with open(file_path, 'rb') as f:
                    content = f.read().decode('latin-1', errors='ignore')
                    
                    # Look for text between BT and ET markers (basic PDF text)
                    import re
                    text_matches = re.findall(r'BT(.*?)ET', content, re.DOTALL)
                    
                    if text_matches:
                        # Extract readable text from PDF commands
                        extracted = []
                        for match in text_matches:
                            # Look for text in parentheses or brackets
                            text_parts = re.findall(r'[\(\[]([^\)\]]+)[\)\]]', match)
                            extracted.extend(text_parts)
                        
                        return '\n'.join(extracted) if extracted else None
            except:
                pass
        
        # Try as UTF-8 text (fallback for unknown formats)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Check if it's mostly readable text (at least 80% printable)
                printable_chars = sum(1 for c in content if c.isprintable() or c.isspace())
                if len(content) > 0 and (printable_chars / len(content)) > 0.8:
                    return content
        except:
            pass
        
        # Try as other encodings
        for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                    # Basic check for readable content
                    if len([c for c in content if c.isprintable()]) > len(content) * 0.7:
                        return content
            except:
                continue
        
        return None
        
    except Exception as e:
        print(f"Error extracting text: {e}")
        return None

@app.route('/')
def home():
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>File Encryption Tool - Live Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; background: #f5f5f5; }
            .header { background: #2c3e50; color: white; padding: 20px; text-align: center; border-radius: 10px; margin-bottom: 20px; }
            .section { background: white; padding: 20px; margin: 20px 0; border-radius: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
            .btn { background: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 5px; border: none; cursor: pointer; }
            .btn-success { background: #27ae60; }
            .btn-danger { background: #e74c3c; }
            .btn:hover { opacity: 0.9; }
            textarea { width: 100%; height: 120px; padding: 10px; border: 2px solid #ddd; border-radius: 5px; font-family: monospace; }
            .result { margin: 15px 0; padding: 15px; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .demo-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
            .card { background: #ecf0f1; padding: 15px; border-radius: 5px; text-align: center; }
            .encrypted-text { background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; word-break: break-all; font-size: 12px; max-height: 100px; overflow-y: auto; border: 1px solid #dee2e6; }
            .file-info { background: #e3f2fd; padding: 8px; border-radius: 4px; margin: 5px 0; font-size: 12px; }
            input[type="file"] { padding: 8px; border: 2px dashed #007bff; border-radius: 5px; width: 100%; background: #f8f9fa; }
            input[type="radio"] { margin-right: 5px; }
            .content-display { max-height: 200px; overflow-y: auto; background: white; padding: 8px; border: 1px solid #ddd; border-radius: 3px; white-space: pre-wrap; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 File Encryption Tool</h1>
            <p>Operating Systems Project - Live Demo</p>
        </div>
        
        <div class="section">
            <h2>🎯 Project Overview</h2>
            <p>This is a comprehensive file encryption tool demonstrating Operating Systems concepts:</p>
            <div class="demo-grid">
                <div class="card">
                    <h4>🔑 Key Management</h4>
                    <p>Generate secure encryption keys</p>
                </div>
                <div class="card">
                    <h4>🔒 File Encryption</h4>
                    <p>Encrypt any file type securely</p>
                </div>
                <div class="card">
                    <h4>🔓 File Decryption</h4>
                    <p>Decrypt with correct keys</p>
                </div>
                <div class="card">
                    <h4>💻 Multiple UIs</h4>
                    <p>Console, GUI, and web interfaces</p>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🚀 Interactive Demo</h2>
            <p><strong>Try the encryption tool right here in your browser!</strong></p>
            
            <h3>Step 1: Generate Encryption Key</h3>
            <button class="btn btn-success" onclick="generateKey()">🔑 Generate New Key</button>
            <div id="keyResult"></div>
            
            <h3>Step 2: Choose Input Method</h3>
            <div style="margin-bottom: 15px;">
                <label style="margin-right: 20px;">
                    <input type="radio" name="inputMethod" value="text" checked onchange="toggleInputMethod()"> 
                    📝 Enter Text Manually
                </label>
                <label>
                    <input type="radio" name="inputMethod" value="file" onchange="toggleInputMethod()"> 
                    📁 Browse & Select File
                </label>
            </div>

            <div id="textInput">
                <textarea id="plainText" placeholder="Enter your text here to encrypt...">Hello! This is a test message for the file encryption tool.

This tool demonstrates:
- File system operations
- Security mechanisms  
- Cryptographic operations
- User interface design

Operating Systems Project - 2025</textarea>
            </div>

            <div id="fileInput" style="display: none;">
                <input type="file" id="fileSelector" accept="*/*" onchange="handleFileSelect()" style="margin-bottom: 10px;">
                <div id="filePreview" style="background: #f8f9fa; padding: 10px; border-radius: 5px; margin-top: 10px; font-family: monospace; display: none;">
                    <strong>Selected File:</strong><br>
                    <span id="fileName"></span><br>
                    <span id="fileSize"></span><br><br>
                    <strong>File Content Preview:</strong><br>
                    <div id="fileContent" style="max-height: 100px; overflow-y: auto; background: white; padding: 8px; border: 1px solid #ddd; border-radius: 3px;"></div>
                </div>
            </div>

            <br>
            <button class="btn" onclick="encryptContent()">🔒 Encrypt Content</button>
            <div id="encryptResult"></div>
            
            <h3>Step 3: Decrypt Content</h3>
            <button class="btn btn-danger" onclick="decryptText()">🔓 Decrypt Content</button>
            <div id="decryptResult"></div>
        </div>

        <footer style="background: #2c3e50; color: white; text-align: center; padding: 20px; border-radius: 10px; margin-top: 30px;">
            <p>🔐 File Encryption Tool - Operating Systems Project 2025</p>
            <p>Built with Python | Secured with AES-256 | Cross-platform Compatible</p>
        </footer>

        <script>
            let currentKey = null;
            let encryptedData = null;
            let selectedFile = null;

            function toggleInputMethod() {
                const method = document.querySelector('input[name="inputMethod"]:checked').value;
                const textInput = document.getElementById('textInput');
                const fileInput = document.getElementById('fileInput');
                
                if (method === 'text') {
                    textInput.style.display = 'block';
                    fileInput.style.display = 'none';
                    selectedFile = null;
                } else {
                    textInput.style.display = 'none';
                    fileInput.style.display = 'block';
                }
            }

            function handleFileSelect() {
                const fileSelector = document.getElementById('fileSelector');
                const file = fileSelector.files[0];
                
                if (file) {
                    selectedFile = file;
                    
                    // Show file info
                    document.getElementById('fileName').textContent = file.name;
                    document.getElementById('fileSize').textContent = formatFileSize(file.size) + ' (' + (file.type || 'unknown type') + ')';
                    
                    // Show preview for text files
                    if (file.type.startsWith('text/') || file.name.endsWith('.txt') || file.name.endsWith('.md') || file.name.endsWith('.py') || file.name.endsWith('.html') || file.name.endsWith('.css') || file.name.endsWith('.js')) {
                        const reader = new FileReader();
                        reader.onload = function(e) {
                            const content = e.target.result;
                            document.getElementById('fileContent').textContent = content.length > 200 ? content.substring(0, 200) + '...' : content;
                            document.getElementById('filePreview').style.display = 'block';
                        };
                        reader.readAsText(file);
                    } else {
                        document.getElementById('fileContent').innerHTML = '<em>[File selected - preview not available for this format]</em>';
                        document.getElementById('filePreview').style.display = 'block';
                    }
                }
            }

            function formatFileSize(bytes) {
                if (bytes === 0) return '0 Bytes';
                const k = 1024;
                const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
            }

            function generateKey() {
                fetch('/generate_key', { method: 'POST' })
                    .then(response => response.json())
                    .then(result => {
                        const keyResultDiv = document.getElementById('keyResult');
                        if (result.success) {
                            currentKey = result.key;
                            keyResultDiv.innerHTML = '<div class="result success"><strong>✅ ' + result.message + '</strong><br><small>🔒 Key generated and ready for encryption!</small></div>';
                        } else {
                            keyResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
                        }
                    })
                    .catch(error => {
                        document.getElementById('keyResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
                    });
            }

            function encryptContent() {
                const method = document.querySelector('input[name="inputMethod"]:checked').value;
                let contentToEncrypt = '';
                let contentName = '';
                
                if (method === 'text') {
                    contentToEncrypt = document.getElementById('plainText').value;
                    contentName = 'Manual Text Input';
                    if (!contentToEncrypt.trim()) {
                        document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Please enter some text to encrypt!</div>';
                        return;
                    }
                    performEncryption(contentToEncrypt, contentName, 'text/plain');
                } else {
                    if (!selectedFile) {
                        document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Please select a file to encrypt!</div>';
                        return;
                    }
                    
                    const reader = new FileReader();
                    reader.onload = function(e) {
                        contentToEncrypt = e.target.result;
                        contentName = selectedFile.name;
                        performEncryption(contentToEncrypt, contentName, selectedFile.type || 'application/octet-stream');
                    };
                    
                    // Read file as base64 for binary files, text for text files
                    if (selectedFile.type.startsWith('text/') || selectedFile.name.endsWith('.txt') || selectedFile.name.endsWith('.md') || selectedFile.name.endsWith('.py') || selectedFile.name.endsWith('.html') || selectedFile.name.endsWith('.css') || selectedFile.name.endsWith('.js')) {
                        reader.readAsText(selectedFile);
                    } else {
                        reader.readAsDataURL(selectedFile); // This will be base64 encoded
                    }
                }
            }

            function performEncryption(content, contentName, contentType) {
                fetch('/encrypt_content', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        content: content,
                        content_name: contentName,
                        content_type: contentType
                    })
                })
                .then(response => response.json())
                .then(result => {
                    const encryptResultDiv = document.getElementById('encryptResult');
                    if (result.success) {
                        currentKey = result.key;
                        encryptedData = result.encrypted_data;
                        encryptResultDiv.innerHTML = '<div class="result success"><strong>✅ ' + result.message + '</strong><br><small>📁 Content: ' + contentName + '</small><div class="encrypted-text"><strong>Encrypted Data:</strong><br>' + result.encrypted_data + '</div><small>🔐 Content successfully encrypted with AES-256! Ready for decryption.</small></div>';
                    } else {
                        encryptResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
                    }
                })
                .catch(error => {
                    document.getElementById('encryptResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
                });
            }

            function decryptText() {
                if (!currentKey || !encryptedData) {
                    document.getElementById('decryptResult').innerHTML = '<div class="result error">❌ Please encrypt some content first!</div>';
                    return;
                }

                fetch('/decrypt_text', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ 
                        encrypted_data: encryptedData, 
                        key: currentKey,
                        original_type: selectedFile ? selectedFile.type : 'text/plain',
                        original_name: selectedFile ? selectedFile.name : 'Manual Text'
                    })
                })
                .then(response => response.json())
                .then(result => {
                    const decryptResultDiv = document.getElementById('decryptResult');
                    if (result.success) {
                        let displayContent = '';
                        
                        if (result.is_binary) {
                            displayContent = `<strong>📁 File Type:</strong> ${result.file_type}<br>
                                            <strong>📊 File Size:</strong> ${result.file_size} bytes<br>
                                            <strong>✅ Status:</strong> File decrypted successfully!<br>
                                            <small>💡 This file format doesn't contain extractable text content.</small>`;
                        } else {
                            displayContent = `<strong>Extracted Text Content:</strong><br>`;
                            if (result.file_info) {
                                displayContent += `<small>${result.file_info}</small><br>`;
                            }
                            displayContent += `<div class="content-display">${result.decrypted_text}</div>`;
                        }
                        
                        decryptResultDiv.innerHTML = `<div class="result success"><strong>✅ ${result.message}</strong><br>${displayContent}<small>🎉 Perfect! Content successfully decrypted and processed.</small></div>`;
                    } else {
                        decryptResultDiv.innerHTML = '<div class="result error">❌ ' + result.message + '</div>';
                    }
                })
                .catch(error => {
                    document.getElementById('decryptResult').innerHTML = '<div class="result error">❌ Error: ' + error.message + '</div>';
                });
            }

            // Auto-generate key on page load
            window.onload = function() {
                setTimeout(generateKey, 1000);
            };
        </script>
    </body>
    </html>
    ''')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    try:
        key = encryptor.generate_key()
        key_b64 = base64.b64encode(key).decode('utf-8')
        return jsonify({'success': True, 'message': 'New encryption key generated!', 'key': key_b64})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/encrypt_content', methods=['POST'])
def encrypt_content():
    try:
        data = request.json
        content = data.get('content', '')
        content_name = data.get('content_name', 'content')
        content_type = data.get('content_type', 'text/plain')
        
        if not content:
            return jsonify({'success': False, 'message': 'No content provided'})
        
        if encryptor.key is None:
            encryptor.generate_key()
        
        # Handle base64 data (for binary files)
        if content.startswith('data:'):
            # Extract the base64 part
            content = content.split(',')[1]
            import base64 as b64
            content_bytes = b64.b64decode(content)
        else:
            # Regular text content
            content_bytes = content.encode('utf-8')
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as temp_file:
            temp_file.write(content_bytes)
            temp_filename = temp_file.name
        
        # Encrypt the file
        encrypted_filename = encryptor.encrypt_file(temp_filename)
        
        # Read encrypted content
        with open(encrypted_filename, 'rb') as f:
            encrypted_data = f.read()
        
        # Clean up
        os.unlink(temp_filename)
        os.unlink(encrypted_filename)
        
        # Convert to base64
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        key_b64 = base64.b64encode(encryptor.key).decode('utf-8')
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_b64,
            'key': key_b64,
            'message': f'Content "{content_name}" encrypted successfully!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text():
    try:
        data = request.json
        encrypted_b64 = data.get('encrypted_data', '')
        key_b64 = data.get('key', '')
        original_type = data.get('original_type', 'text/plain')
        original_name = data.get('original_name', 'content')
        
        if not encrypted_b64 or not key_b64:
            return jsonify({'success': False, 'message': 'Missing encrypted data or key'})
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_b64)
        key = base64.b64decode(key_b64)
        
        # Set the key
        from cryptography.fernet import Fernet
        encryptor.key = key
        encryptor.fernet = Fernet(key)
        
        # Create temporary encrypted file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.encrypted') as temp_file:
            temp_file.write(encrypted_data)
            temp_encrypted_filename = temp_file.name
        
        # Decrypt the file
        decrypted_filename = encryptor.decrypt_file(temp_encrypted_filename)
        
        # Get file size
        file_size = os.path.getsize(decrypted_filename)
        
        # Try to extract text content from various file formats
        extracted_text = extract_text_from_file(decrypted_filename, original_name, original_type)
        
        # Clean up
        os.unlink(temp_encrypted_filename)
        os.unlink(decrypted_filename)
        
        if extracted_text:
            return jsonify({
                'success': True,
                'is_binary': False,
                'decrypted_text': extracted_text,
                'file_info': f"File: {original_name} ({original_type}) - {file_size} bytes",
                'message': f'Text extracted from "{original_name}" successfully!'
            })
        else:
            return jsonify({
                'success': True,
                'is_binary': True,
                'file_type': original_type or 'Unknown',
                'file_size': file_size,
                'message': f'File "{original_name}" decrypted successfully (no text content extractable)'
            })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
