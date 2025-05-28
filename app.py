import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from flask_socketio import SocketIO, emit, join_room
from passlib.hash import sha256_crypt
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from datetime import datetime
import io

app = Flask(__name__)
app.secret_key = 'mysecretkey'  # Replace with a secure key in production
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
socketio = SocketIO(app)

# Cipher class for encryption/decryption
class Cipher:
    def __init__(self):
        self.key_pair = RSA.generate(2048)
        self.public_key = self.key_pair.publickey().export_key()
        self.private_key = self.key_pair.export_key()

    def encrypt_rsa(self, message, public_key):
        recipient_key = RSA.import_key(public_key)
        cipher = PKCS1_OAEP.new(recipient_key)
        return b64encode(cipher.encrypt(message.encode())).decode()

    def decrypt_rsa(self, encrypted_message, private_key):
        private_key = RSA.import_key(private_key)
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(b64decode(encrypted_message)).decode()

    def encrypt_aes(self, data, key):
        cipher = AES.new(key, AES.MODE_EAX)
        if isinstance(data, str):
            data = data.encode()
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return b64encode(cipher.nonce).decode(), b64encode(ciphertext).decode()

    def decrypt_aes(self, encrypted_data, key, iv):
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(iv))
        return cipher.decrypt(b64decode(encrypted_data))

# Database setup
def init_db():
    conn = sqlite3.connect('encrypto_chat.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT,
            private_key TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            cipher TEXT,
            encrypted_message TEXT,
            iv TEXT,
            encrypted_key TEXT,
            file_name TEXT DEFAULT '',
            file_type TEXT DEFAULT '',
            is_file BOOLEAN DEFAULT FALSE,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('encrypto_chat.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def main():
    return render_template('main.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cipher = Cipher()
        public_key = cipher.public_key.decode('utf-8')
        private_key = cipher.private_key.decode('utf-8')
        
        hashed_password = sha256_crypt.hash(password)
        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute('INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)',
                          (username, hashed_password, public_key, private_key))
            conn.commit()
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error='Username already exists')
        finally:
            conn.close()
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and sha256_crypt.verify(password, user['password']):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = username
            session.permanent = True
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session['username'])

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        search_term = request.form['search']
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT username FROM users WHERE username LIKE ? AND id != ?',
                      (f'%{search_term}%', session['user_id']))
        users = cursor.fetchall()
        conn.close()
        return render_template('search.html', users=users)
    return render_template('search.html')

@app.route('/chat/<username>', methods=['GET', 'POST'])
def chat(username):
    if 'user_id' not in session:
        if request.method == 'POST':
            return jsonify({'error': 'Not logged in'}), 401
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, username, public_key FROM users WHERE username = ?', (username,))
    receiver = cursor.fetchone()
    
    if not receiver:
        conn.close()
        if request.method == 'POST':
            return jsonify({'error': 'User not found'}), 404
        return render_template('chat.html', username=username, error='User not found')
    
    receiver_id = receiver['id']
    
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        if file and file.filename:
            try:
                cipher = Cipher()
                key = get_random_bytes(16)
                iv, encrypted_file = cipher.encrypt_aes(file.read(), key)
                encrypted_key = cipher.encrypt_rsa(b64encode(key).decode(), receiver['public_key'])
                
                cursor.execute('''
                    INSERT INTO messages (sender_id, receiver_id, cipher, encrypted_message, iv, encrypted_key, file_name, file_type, is_file)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (session['user_id'], receiver_id, 'AES', encrypted_file, iv, encrypted_key, file.filename, file.mimetype, True))
                conn.commit()
                
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                message_id = cursor.lastrowid
                
                socketio.emit('message', {
                    'sender': session['username'],
                    'message': encrypted_file,
                    'cipher': 'AES',
                    'is_encrypted': True,
                    'is_file': True,
                    'file_name': file.filename,
                    'file_type': file.mimetype,
                    'timestamp': timestamp,
                    'message_id': message_id
                }, room=str(session['user_id']))
                
                socketio.emit('message', {
                    'sender': session['username'],
                    'message': file.filename,
                    'cipher': 'AES',
                    'is_encrypted': False,
                    'is_file': True,
                    'file_name': file.filename,
                    'file_type': file.mimetype,
                    'timestamp': timestamp,
                    'message_id': message_id
                }, room=str(receiver_id))
                
                conn.close()
                return jsonify({'success': True, 'message': 'File uploaded successfully'}), 200
            except Exception as e:
                conn.close()
                return jsonify({'error': f'File upload failed: {str(e)}'}), 500
        else:
            conn.close()
            return jsonify({'error': 'No file provided'}), 400
    
    cursor.execute('SELECT private_key FROM users WHERE id = ?', (session['user_id'],))
    user_private_key_row = cursor.fetchone()
    if not user_private_key_row:
        conn.close()
        return render_template('chat.html', username=username, error='User private key not found. Please log in again.')
    user_private_key = user_private_key_row['private_key']
    
    cursor.execute('''
        SELECT m.*, u1.username AS sender_username, u2.username AS receiver_username
        FROM messages m
        LEFT JOIN users u1 ON m.sender_id = u1.id
        LEFT JOIN users u2 ON m.receiver_id = u2.id
        WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.timestamp
    ''', (session['user_id'], receiver_id, receiver_id, session['user_id']))
    messages = cursor.fetchall()
    
    processed_messages = []
    cipher = Cipher()
    
    for msg in messages:
        message_data = {
            'sender': msg['sender_username'] if msg['sender_username'] else 'Unknown',
            'cipher': msg['cipher'] if msg['cipher'] else 'Unknown',
            'timestamp': msg['timestamp'] if msg['timestamp'] else 'N/A',
            'is_file': bool(msg['is_file'] or False),
            'file_name': msg['file_name'] if msg['file_name'] else '',
            'file_type': msg['file_type'] if msg['file_type'] else '',
            'message_id': msg['id']
        }
        
        if msg['sender_id'] == session['user_id']:
            message_data['message'] = msg['encrypted_message'] if msg['encrypted_message'] else 'N/A'
            message_data['is_encrypted'] = True
        elif msg['receiver_id'] == session['user_id']:
            try:
                if msg['cipher'] == 'AES':
                    encrypted_key = msg['encrypted_key'] if msg['encrypted_key'] else ''
                    if not encrypted_key:
                        raise ValueError("Encrypted key missing")
                    key = cipher.decrypt_rsa(encrypted_key, user_private_key)
                    key = b64decode(key)
                    if msg['is_file']:
                        message_data['message'] = msg['file_name'] if msg['file_name'] else 'N/A'
                    else:
                        iv = msg['iv'] if msg['iv'] else ''
                        if not iv:
                            raise ValueError("IV missing")
                        decrypted_message = cipher.decrypt_aes(msg['encrypted_message'], key, iv).decode()
                        message_data['message'] = decrypted_message
                else:
                    decrypted_message = cipher.decrypt_rsa(msg['encrypted_message'], user_private_key)
                    message_data['message'] = decrypted_message
                message_data['is_encrypted'] = False
            except Exception as e:
                message_data['message'] = f"Decryption error: {str(e)}"
                message_data['is_encrypted'] = True
        else:
            message_data['message'] = "Unauthorized"
            message_data['is_encrypted'] = True
            
        processed_messages.append(message_data)
    
    conn.close()
    return render_template('chat.html', username=username, messages=processed_messages, receiver_id=receiver_id, session=session)

@app.route('/download/<int:message_id>')
def download_file(message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT m.*, u.private_key
        FROM messages m
        JOIN users u ON u.id = ?
        WHERE m.id = ? AND m.is_file = 1 AND m.receiver_id = ?
    ''', (session['user_id'], message_id, session['user_id']))
    message = cursor.fetchone()
    
    if not message:
        conn.close()
        return jsonify({'error': 'File not found or unauthorized'}), 404
    
    try:
        cipher = Cipher()
        key = cipher.decrypt_rsa(message['encrypted_key'], message['private_key'])
        key = b64decode(key)
        decrypted_data = cipher.decrypt_aes(message['encrypted_message'], key, message['iv'])
        
        return send_file(
            io.BytesIO(decrypted_data),
            download_name=message['file_name'],
            mimetype=message['file_type'],
            as_attachment=True
        )
    except Exception as e:
        conn.close()
        return jsonify({'error': f'Decryption error: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/delete_chat/<username>', methods=['POST'])
def delete_chat(username):
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not logged in'}), 401
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    receiver = cursor.fetchone()
    
    if not receiver:
        conn.close()
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    try:
        cursor.execute('''
            DELETE FROM messages
            WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
        ''', (session['user_id'], receiver['id'], receiver['id'], session['user_id']))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    except Exception as e:
        conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('login'))

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(str(session['user_id']))
        emit('user_connected', {'user_id': session['user_id']})

@socketio.on('join')
def on_join(data):
    user_id = data['user_id']
    join_room(str(user_id))

@socketio.on('message')
def handle_message(data):
    sender_id = session['user_id']
    receiver_username = data['receiver']
    message = data['message']
    cipher = data['cipher']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id, public_key FROM users WHERE username = ?', (receiver_username,))
    receiver = cursor.fetchone()
    
    if not receiver:
        conn.close()
        return
    
    cipher_obj = Cipher()
    key = get_random_bytes(16)
    encrypted_key = None
    iv = None
    if cipher == 'AES':
        iv, encrypted_message = cipher_obj.encrypt_aes(message, key)
        encrypted_key = cipher_obj.encrypt_rsa(b64encode(key).decode(), receiver['public_key'])
    else:
        encrypted_message = cipher_obj.encrypt_rsa(message, receiver['public_key'])
    
    cursor.execute('''
        INSERT INTO messages (sender_id, receiver_id, cipher, encrypted_message, iv, encrypted_key)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (sender_id, receiver['id'], cipher, encrypted_message, iv, encrypted_key))
    conn.commit()
    
    message_id = cursor.lastrowid
    conn.close()
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    emit('message', {
        'sender': session['username'],
        'message': encrypted_message,
        'cipher': cipher,
        'is_encrypted': True,
        'is_file': False,
        'timestamp': timestamp,
        'message_id': message_id
    }, room=str(sender_id))
    
    emit('message', {
        'sender': session['username'],
        'message': message,
        'cipher': cipher,
        'is_encrypted': False,
        'is_file': False,
        'timestamp': timestamp,
        'message_id': message_id
    }, room=str(receiver['id']))

@socketio.on('switch_cipher')
def switch_cipher(data):
    emit('cipher_switched', {'cipher': data['cipher']}, broadcast=True)

@socketio.on('delete_chat')
def handle_delete_chat(data):
    receiver_username = data['receiver']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (receiver_username,))
    receiver = cursor.fetchone()
    
    if receiver:
        emit('chat_deleted', room=str(session['user_id']))
        emit('chat_deleted', room=str(receiver['id']))
    conn.close()

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True)