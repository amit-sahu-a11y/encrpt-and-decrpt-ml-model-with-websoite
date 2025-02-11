import os
import io
from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

app = Flask(__name__)
# This secret key is for Flask session management. It must be kept secret.
app.secret_key = 'your_flask_session_secret_here'  # Change this!

# In-memory user store (for demonstration only)
users = {}

# ---------------------------
# Encryption Key Management
# ---------------------------
KEY_FILE = 'secret.key'

def generate_key(key_path=KEY_FILE):
    """
    Generates a new 32-byte url-safe base64-encoded key for Fernet
    and saves it to a file.
    """
    key = Fernet.generate_key()  # Valid key of 32 bytes (base64-encoded)
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
    print(f"New key generated and saved to '{key_path}'.")
    return key

def load_key(key_path=KEY_FILE):
    """
    Loads the encryption key from a file. If the file does not exist or
    if the key is invalid, a new key is generated.
    """
    if not os.path.exists(key_path):
        return generate_key(key_path)
    
    with open(key_path, 'rb') as key_file:
        key = key_file.read().strip()  # Remove any accidental whitespace/newlines

    # Validate the key by trying to create a Fernet instance.
    try:
        Fernet(key)
    except Exception as e:
        print(f"Invalid key detected in '{key_path}': {e}")
        print("Regenerating a new key...")
        return generate_key(key_path)
    
    return key

# Load (or generate) the encryption key at startup.
key = load_key()

# ---------------------------
# Encryption / Decryption Functions
# ---------------------------
def encrypt_text_func(text, key):
    """Encrypts a text string using the provided key."""
    fernet = Fernet(key)
    encrypted_bytes = fernet.encrypt(text.encode('utf-8'))
    return encrypted_bytes.decode('utf-8')

def decrypt_text_func(encrypted_text, key):
    """Decrypts a text string using the provided key."""
    fernet = Fernet(key)
    decrypted_bytes = fernet.decrypt(encrypted_text.encode('utf-8'))
    return decrypted_bytes.decode('utf-8')

def encrypt_bytes(data, key):
    """Encrypts binary data using the provided key."""
    fernet = Fernet(key)
    return fernet.encrypt(data)

def decrypt_bytes(encrypted_data, key):
    """Decrypts binary data using the provided key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)

# ---------------------------
# Routes
# ---------------------------
@app.route('/')
def index():
    # Redirect to dashboard if already signed in.
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        if username in users:
            flash('Username already exists. Please choose another one.')
            return redirect(url_for('signup'))
        users[username] = generate_password_hash(password)
        flash('Sign up successful. Please sign in.')
        return redirect(url_for('signin'))
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        username = request.form.get('username').strip()
        password = request.form.get('password').strip()
        if username in users and check_password_hash(users[username], password):
            session['username'] = username
            flash('Sign in successful.')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.')
            return redirect(url_for('signin'))
    return render_template('signin.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('signin'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/process_text', methods=['POST'])
def process_text():
    if 'username' not in session:
        return redirect(url_for('signin'))
    action = request.form.get('action')  # Expected "encrypt" or "decrypt"
    text = request.form.get('text')
    result = ""
    try:
        if action == 'encrypt':
            result = encrypt_text_func(text, key)
        elif action == 'decrypt':
            result = decrypt_text_func(text, key)
        else:
            result = "Invalid action selected."
    except Exception as e:
        result = f"Error: {str(e)}"
    return render_template('dashboard.html', username=session['username'], text_result=result)

@app.route('/process_file', methods=['POST'])
def process_file():
    if 'username' not in session:
        return redirect(url_for('signin'))
    action = request.form.get('action')  # Expected "encrypt" or "decrypt"
    if 'file' not in request.files:
        flash('No file part in the request.')
        return redirect(url_for('dashboard'))
    file = request.files['file']
    if file.filename == '':
        flash('No file selected.')
        return redirect(url_for('dashboard'))
    
    filename = secure_filename(file.filename)
    file_data = file.read()
    try:
        if action == 'encrypt':
            processed_data = encrypt_bytes(file_data, key)
            out_filename = filename + '.enc'
        elif action == 'decrypt':
            processed_data = decrypt_bytes(file_data, key)
            out_filename = "decrypted_" + filename
        else:
            flash('Invalid action selected.')
            return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f"Error processing file: {str(e)}")
        return redirect(url_for('dashboard'))
    
    return send_file(
        io.BytesIO(processed_data),
        as_attachment=True,
        download_name=out_filename,
        mimetype='application/octet-stream'
    )

if __name__ == '__main__':
    app.run(debug=True)
