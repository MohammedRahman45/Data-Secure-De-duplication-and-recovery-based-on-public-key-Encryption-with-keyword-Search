from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import os
import sqlite3
import hashlib
from twilio.rest import Client
import random
import string

# Twilio configuration
TIWILIO_ACCOUNT_SID= 'XXXXXXXXXXXXXXXXX'
TIWILIO_AUTH_TOKEN= 'XXXXXXXXXXXXXXXXX'
TIWILIO_PHONE-NUMBER= 'XXXXXXXXXXX'


app = Flask(__name__)
app.secret_key = "your_secret_key"
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'pptx'}

# Initialize Twilio client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Database setup
conn = sqlite3.connect('database.db', check_same_thread=False)
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        encryption_key TEXT
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        encrypted_data BLOB,
        encryption_key TEXT,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
''')

conn.commit()
conn.close()

# Utility functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to generate a random key
def generate_random_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

def encrypt_AES(data, key):
    derived_key = PBKDF2(key.encode(), b'salt', dkLen=32)  # 32 bytes key length for AES-256
    cipher = AES.new(derived_key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return nonce + tag + ciphertext

def decrypt_AES(data, key):
    derived_key = PBKDF2(key.encode(), b'salt', dkLen=32)  # 32 bytes key length for AES-256
    nonce = data[:16]
    tag = data[16:32]
    ciphertext = data[32:]
    cipher = AES.new(derived_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted_data

# Routes
@app.route('/')
def index():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        encryption_key = request.form['encryption_key']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, encryption_key) VALUES (?, ?, ?)", (username, password, encryption_key))
        conn.commit()
        conn.close()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        user = c.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]  # Store user_id in session upon successful login
            flash('Login successful!', 'success')
            return redirect(url_for('file_management'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Clear user session upon logout
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/file-management')
def file_management():
    if 'user_id' not in session:
        flash('User not logged in', 'error')
        return redirect(url_for('login'))

    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row  # Set row_factory to sqlite3.Row to fetch rows as dictionaries
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE user_id=?", (session['user_id'],))
    files = c.fetchall()
    conn.close()
    return render_template('file_management.html', files=files)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'error')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'error')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Get user_id of current user
        if 'user_id' not in session:
            flash('User not logged in', 'error')
            return redirect(url_for('login'))

        user_id = session['user_id']

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT encryption_key FROM users WHERE id=?", (user_id,))
        user_encryption_key = c.fetchone()[0]
        conn.close()

        encrypted_data = None
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'rb') as f:
            encrypted_data = encrypt_AES(f.read(), user_encryption_key)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO files (filename, encrypted_data, encryption_key, user_id) VALUES (?, ?, ?, ?)",
                  (filename, sqlite3.Binary(encrypted_data), user_encryption_key, user_id))
        conn.commit()
        conn.close()

        flash('File uploaded successfully', 'success')
    else:
        flash('Invalid file type', 'error')
    return redirect(url_for('file_management'))

@app.route('/decrypt-file/<int:file_id>', methods=['POST'])
def decrypt_file(file_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM files WHERE id=?", (file_id,))
    file_data = c.fetchone()
    
    if not file_data:
        flash('File not found', 'error')
        conn.close()
        return redirect(url_for('file_management'))

    random_encryption_key = generate_random_key()
    
    #print(random_encryption_key)

    # Send encryption key to user's mobile number
    client.messages.create(
        to="+919396778322",  # Replace with user's mobile number from the database
        from_=TWILIO_PHONE_NUMBER,
        body=f"Your decryption key for file {file_data[1]} is: {random_encryption_key}",
    )

    # Store file ID and expected encryption key in session for later verification
    session['file_id'] = file_id
    session['expected_encryption_key'] = random_encryption_key

    flash('Decryption key sent to your mobile number', 'success')

    conn.close()
    return redirect(url_for('enter_decryption_key'))

@app.route('/enter-decryption-key', methods=['GET', 'POST'])
def enter_decryption_key():
    error_message = None

    if request.method == 'POST':
        entered_encryption_key = request.form.get('encryption_key')
        expected_encryption_key = session.get('expected_encryption_key')

        if entered_encryption_key == expected_encryption_key:
            file_id = session.get('file_id')
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute("SELECT * FROM files WHERE id=?", (file_id,))
            file_data = c.fetchone()

            encrypted_data = file_data[2]  # Access encrypted_data using integer index
            key = file_data[3]
            decrypted_data = decrypt_AES(encrypted_data, key)

            decrypted_filename = f"decrypted_{file_data[1]}"  # Access filename using integer index
            decrypted_filepath = os.path.join(app.config['UPLOAD_FOLDER'], decrypted_filename)

            with open(decrypted_filepath, 'wb') as f:  # Use 'wb' mode for writing binary data
                f.write(decrypted_data)

            conn.close()
            return send_file(decrypted_filepath, as_attachment=True)
        else:
            error_message = 'Incorrect key'

    return render_template('enter_decryption_key.html', error_message=error_message)


if __name__ == '__main__':
    app.run(debug=True)
