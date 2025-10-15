"""
Web Demo Version of File Encryption Tool
This creates a simple web interface for demonstration purposes
"""

from flask import Flask, render_template, request, jsonify, send_file
import os
import tempfile
from werkzeug.utils import secure_filename
from encryption_module import FileEncryptor
import base64

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5MB max file size

# Global encryptor instance
encryptor = FileEncryptor()

@app.route('/')
def index():
    return render_template('demo.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    try:
        key = encryptor.generate_key()
        # Convert key to base64 for web transmission
        key_b64 = base64.b64encode(key).decode('utf-8')
        return jsonify({
            'success': True, 
            'message': 'New encryption key generated!',
            'key': key_b64
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    try:
        data = request.json
        text = data.get('text', '')
        
        if not text:
            return jsonify({'success': False, 'message': 'No text provided'})
        
        if encryptor.key is None:
            encryptor.generate_key()
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            temp_file.write(text)
            temp_filename = temp_file.name
        
        # Encrypt the file
        encrypted_filename = encryptor.encrypt_file(temp_filename)
        
        # Read encrypted content
        with open(encrypted_filename, 'rb') as f:
            encrypted_data = f.read()
        
        # Clean up
        os.unlink(temp_filename)
        os.unlink(encrypted_filename)
        
        # Convert to base64 for web transmission
        encrypted_b64 = base64.b64encode(encrypted_data).decode('utf-8')
        key_b64 = base64.b64encode(encryptor.key).decode('utf-8')
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted_b64,
            'key': key_b64,
            'message': 'Text encrypted successfully!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text():
    try:
        data = request.json
        encrypted_b64 = data.get('encrypted_data', '')
        key_b64 = data.get('key', '')
        
        if not encrypted_b64 or not key_b64:
            return jsonify({'success': False, 'message': 'Missing encrypted data or key'})
        
        # Decode from base64
        encrypted_data = base64.b64decode(encrypted_b64)
        key = base64.b64decode(key_b64)
        
        # Set the key
        encryptor.key = key
        encryptor.fernet = encryptor.fernet = encryptor.__class__.__module__.split('.')[0] and __import__('cryptography.fernet', fromlist=['Fernet']).Fernet(key)
        
        # Create temporary encrypted file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.encrypted') as temp_file:
            temp_file.write(encrypted_data)
            temp_encrypted_filename = temp_file.name
        
        # Decrypt the file
        decrypted_filename = encryptor.decrypt_file(temp_encrypted_filename)
        
        # Read decrypted content
        with open(decrypted_filename, 'r', encoding='utf-8') as f:
            decrypted_text = f.read()
        
        # Clean up
        os.unlink(temp_encrypted_filename)
        os.unlink(decrypted_filename)
        
        return jsonify({
            'success': True,
            'decrypted_text': decrypted_text,
            'message': 'Text decrypted successfully!'
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
