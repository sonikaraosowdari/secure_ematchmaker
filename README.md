from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps
from cryptography.fernet import Fernet
import uuid
import datetime
import json
import pyotp
import qrcode
from io import BytesIO
from flask import send_file

app = Flask(__name__)
bcrypt = Bcrypt(app)

SECRET_KEY = 'your_secret_key'

# Generate an encryption key (keep this secret!)
ENCRYPTION_KEY = Fernet.generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)

# Mock database
users = {
    "test@example.com": {
        "password": "hashed_password",
        "profile": {
            "name": "Test User",
            "bio": "Hello, I love coding!",
            "preferences": "Secure matchmaker platforms"
        }
    }
}

# Mock message database
messages = []

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify(message="Token is missing"), 401
        try:
            jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify(message="Token has expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(message="Invalid token"), 401
        return f(*args, **kwargs)
    return decorated

# File paths for persistence
USERS_FILE = "users.json"
MESSAGES_FILE = "messages.json"

# Save data to files
def save_data():
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)
    with open(MESSAGES_FILE, "w") as f:
        json.dump(messages, f)

# Load data from files
def load_data():
    global users, messages
    try:
        with open(USERS_FILE, "r") as f:
            users = json.load(f)
    except FileNotFoundError:
        users = {}

    try:
        with open(MESSAGES_FILE, "r") as f:
            messages = json.load(f)
    except FileNotFoundError:
        messages = []

# Loading existing data
load_data()

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()  
    email = data['email']
    password = data['password']

    # Hashing the password using bcrypt
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    # Generating a TOTP secret key
    totp_secret = pyotp.random_base32()

    # Saving the user in the database
    users[email] = {'password': hashed_password}
    save_data()
    return jsonify(
        message="User registered successfully",
        totp_secret=totp_secret
        ), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()  # Getting user input
    email = data['email']
    password = data['password']
    totp_code = data.get('totp_code')

    # Checking if user exists in the mock database
    user = users.get(email)
    if user and bcrypt.check_password_hash(user['password'], password):
        totp = pyotp.TOTP(user['totp_secret'])

        # Verify TOTP code
        if not totp.verify(totp_code):
            return jsonify(message="Invalid MFA code"), 401

         # Generate JWT token
        token = jwt.encode(
            {'email': email, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY,
            algorithm='HS256'
        )
        return jsonify(token=token), 200
    return jsonify(message="Invalid credentials"), 401

@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify(message="This is a protected route")

@app.route('/profile', methods=['POST'])
@token_required
def create_or_update_profile():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    email = data['email']

    # Get profile data from request
    profile_data = request.get_json()
    name = profile_data.get('name')
    bio = profile_data.get('bio')
    preferences = profile_data.get('preferences')

    # Update the user's profile in the database
    if email in users:
        users[email]['profile'] = {
            "name": name,
            "bio": bio,
            "preferences": preferences
        }
        return jsonify(message="Profile updated successfully"), 200

    return jsonify(message="User not found"), 404


@app.route('/profile', methods=['GET'])
@token_required
def get_profile():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    email = data['email']

    # Retrieve the user's profile
    user = users.get(email)
    if user and 'profile' in user:
        return jsonify(profile=user['profile']), 200

    return jsonify(message="Profile not found"), 404

@app.route('/send-message', methods=['POST'])
@token_required
def send_message():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    sender = data['email']

    message_data = request.get_json()
    recipient = message_data['recipient']
    message = message_data['message']

    # Encrypt the message
    encrypted_message = cipher_suite.encrypt(message.encode())

    # Store the message
    messages.append({
        "id": str(uuid.uuid4()),
        "sender": sender,
        "recipient": recipient,
        "message": encrypted_message.decode('utf-8'),
        "timestamp": datetime.datetime.utcnow().isoformat()
    })
    save_data()
    print(f"Current messages: {messages}")
    return jsonify(message="Message sent successfully"), 200

@app.route('/messages', methods=['GET'])
@token_required
def get_messages():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    recipient = data['email']

    # Filter messages for the recipient
    user_messages = [
        {
            "sender": msg["sender"],
            "message": cipher_suite.decrypt(msg["message"]).decode(),
            "timestamp": msg["timestamp"]
        }
        for msg in messages if msg["recipient"] == recipient
    ]

    return jsonify(messages=user_messages), 200

@app.route('/delete-message', methods=['POST'])
@token_required
def delete_message():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    email = data['email']

    message_data = request.get_json()
    message_id = message_data.get('id')

    # Find and delete the message
    global messages
    messages = [msg for msg in messages if msg["id"] != message_id or (msg["sender"] != email and msg["recipient"] != email)]
    save_data()
    return jsonify(message="Message deleted successfully"), 200

@app.route('/delete-profile', methods=['DELETE'])
@token_required
def delete_profile():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    email = data['email']

    # Remove user from users database
    if email in users:
        del users[email]

    # Remove messages sent or received by the user
    global messages
    messages = [msg for msg in messages if msg["sender"] != email and msg["recipient"] != email]

    # Save updated data
    save_data()

    return jsonify(message="Profile and associated data deleted successfully"), 200

@app.route('/mfa-setup', methods=['GET'])
@token_required
def mfa_setup():
    token = request.headers.get('x-access-token')
    data = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    email = data['email']
    totp_secret = users[email]['totp_secret']

    # Generate TOTP URL
    totp = pyotp.TOTP(totp_secret)
    totp_url = totp.provisioning_uri(email, issuer_name="SecureE-Matchmaker")

    # Generate QR code
    img = qrcode.make(totp_url)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype='image/png')

if __name__ == '__main__':
    app.run(debug=True, port=5001)
