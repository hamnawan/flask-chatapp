import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///your_database.db'  # SQLite database
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
app.config['JWT_EXPIRATION_DELTA'] = timedelta(hours=1)  # Token expiration time
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
socketio = SocketIO(app)


# User model


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    chatroom = db.relationship('ChatRoom', secondary='user_chatroom', back_populates='users')
    messages = db.relationship('Message', back_populates='user')


# ChatRoom Model


class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    users = db.relationship('User', secondary='user_chatroom', back_populates='chatroom')
    messages = db.relationship('Message', backref='chatroom', lazy=True)


# Create an association table for the many-to-many relationship between User and ChatRoom


user_chatroom = db.Table('user_chatroom',
                         db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                         db.Column('chatroom_id', db.Integer, db.ForeignKey('chat_room.id'), primary_key=True)
                         )


#  Message Model


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chat_room.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', back_populates='messages')


# API route for user registration


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, password=hashed_password)

    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


# API route for user login


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({'message': 'Invalid credentials'}), 401

    # Include the 'user_id' claim in the JWT token
    token_payload = {'user_id': user.id, 'exp': datetime.utcnow() + app.config['JWT_EXPIRATION_DELTA']}

    # Generate a JWT token with the 'user_id' claim
    token = jwt.encode(token_payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

    return jsonify({'message': 'Login successful', 'token': token})


# API route for user logout


@app.route('/api/logout', methods=['POST'])
def logout():
    # Implement JWT-based logout if needed
    return jsonify({'message': 'Logout successful'}), 200


# API route for getting a list of chat rooms


@app.route('/api/chat/rooms', methods=['GET'])
def get_chat_rooms():
    chat_rooms = ChatRoom.query.all()
    chat_rooms_data = [{'id': room.id, 'name': room.name, 'description': room.description} for room in chat_rooms]
    return jsonify({'chat_rooms': chat_rooms_data}), 200


# API route for creating a new chat room


@app.route('/api/chat/rooms', methods=['POST'])
def create_chat_room():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    if not name:
        return jsonify({'message': 'Chat room name is required'}), 400

    chat_room = ChatRoom(name=name, description=description)
    db.session.add(chat_room)
    db.session.commit()

    return jsonify({'message': 'Chat room created successfully'}), 201


# API route for getting the details of a specific chat room


@app.route('/api/chat/rooms/<int:room_id>', methods=['GET'])
def get_chat_room_details(room_id):
    chat_room = ChatRoom.query.get(room_id)

    if not chat_room:
        return jsonify({'message': 'Chat room not found'}), 404

    chat_room_data = {
        'id': chat_room.id,
        'name': chat_room.name,
        'description': chat_room.description,
        'users': [{'id': user.id, 'username': user.username} for user in chat_room.users],
        'messages': [{'id': message.id, 'content': message.content, 'user_id': message.user_id} for message in
                     chat_room.messages]
    }

    return jsonify({'chat_room': chat_room_data}), 200


# API route for allowing a user to send a message to a specific chat room
@app.route('/api/chat/rooms/<int:room_id>/messages', methods=['POST'])
def send_message_to_chat_room(room_id):
    data = request.get_json()
    token = data.get('token')
    message_content = data.get('message')

    if not message_content:
        return jsonify({'message': 'Message content is required'}), 400

    # Ensure user is authenticated using JWT
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    user_id = decoded_token['user_id']
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    chat_room = ChatRoom.query.get(room_id)

    if not chat_room:
        return jsonify({'message': 'Chat room not found'}), 404

    # Check if the user is not already a member of the chat room, and if not, add them.
    if user not in chat_room.users:
        chat_room.users.append(user)
        db.session.commit()

    # Now that the user is a member (if they weren't already), proceed to send the message.
    message = Message(content=message_content, user_id=user_id, chatroom_id=room_id)
    db.session.add(message)
    db.session.commit()

    # Broadcast the message to all users in the chat room
    socketio.emit('message', {'sender_id': user_id, 'text': message_content, 'created_at': message.timestamp},
                  room=str(room_id))

    return jsonify({'message': 'Message sent successfully'}), 201


@app.route('/api/chat/rooms/<int:room_id>/messages', methods=['GET'])
def get_chat_room_messages(room_id):
    chat_room = ChatRoom.query.get(room_id)

    if not chat_room:
        return jsonify({'message': 'Chat room not found'}), 404

    messages = Message.query.filter_by(chatroom_id=room_id).all()

    messages_data = [{'id': message.id, 'content': message.content, 'sender_id': message.user_id,
                      'created_at': message.timestamp} for message in messages]

    # Include the chat room ID in the response
    response_data = {'chat_room_id': chat_room.id, 'messages': messages_data}

    return jsonify(response_data), 200


# WebSocket route for real-time chat
@socketio.on('message')
def handle_message(data):
    # Ensure user is authenticated using JWT
    token = data.get('token')
    try:
        decoded_token = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Invalid token'}), 401

    # Extract user_id from the decoded JWT token
    user_id = decoded_token['user_id']

    # Fetch the user from the database using user_id
    user = User.query.get(user_id)

    if not user:
        return jsonify({'message': 'User not found'}), 404

    # Extract other necessary data from the incoming WebSocket message
    username = user.username
    message_content = data.get('message')
    chat_room_id = data.get('chat_room_id')

    # Fetch the chat room from the database using chat_room_id
    chat_room = ChatRoom.query.get(chat_room_id)

    if not chat_room:
        return jsonify({'message': 'Chat room not found'}), 404

    # Create a new message with the content
    message = Message(content=message_content, user_id=user.id, chatroom_id=chat_room.id)
    db.session.add(message)
    db.session.commit()

    # Broadcast the message to all users in the chat room
    emit('message', {'sender': username, 'message': message_content}, room=str(chat_room.id))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    socketio.run(app, debug=True)
