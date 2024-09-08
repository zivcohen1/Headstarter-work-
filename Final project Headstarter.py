from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'thisisthesecretkey'

# In-memory database for users
users_db = {}

# Token-required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_db.get(data['username'])
            if current_user is None:
                raise ValueError("Invalid user")
        except Exception as e:
            return jsonify({"message": str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Route to create a new user (sign up)
@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if not all(key in data for key in ["username", "password"]):
        return jsonify({"message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    if username in users_db:
        return jsonify({"message": "User already exists"}), 409

    hashed_password = generate_password_hash(password, method='sha256')
    users_db[username] = {"password": hashed_password}
    return jsonify({"message": "User created successfully!"}), 201

# Route to log in a user (get a JWT token)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not all(key in data for key in ["username", "password"]):
        return jsonify({"message": "Missing username or password"}), 400

    username = data['username']
    password = data['password']

    user = users_db.get(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = jwt.encode({
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({"token": token})

# Route to get user details (Protected)
@app.route('/user', methods=['GET'])
@token_required
def get_user(current_user):
    return jsonify({"user": current_user})

# Route to log out a user (invalidate token)
@app.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    # For simplicity, we're not managing token revocation here
    return jsonify({"message": "Logged out successfully!"}), 200

# Running the Flask app
if __name__ == '__main__':
    app.run(debug=True)
