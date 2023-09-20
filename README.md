# flask-chatapp
This is a simple Flask-based chat application that allows users to register, login, create chat rooms, and send messages in real-time using websockets. It also includes user authentication with JWT (JSON Web Tokens) and utilizes SQLAlchemy for database operations.
### Requirements
###Functional Requirements
Following are the functions which the application will be able to perform.
* **User Registration (POST /api/register)**
Users should be able to register with a unique username and a password.
The password should be securely hashed and stored in the database.
Registration should return a success message upon successful user creation.

* **User Login (POST /api/login)**
Registered users can log in with their username and password.
The system should verify the provided credentials.
Upon successful login, the system should generate a JWT token containing the user's ID and expiration time.

* **User Logout (POST /api/logout)**
This requirement is not fully implemented in the code, and it typically involves invalidating or deleting the user's JWT token on the server if needed.

* **Chat Room Management**
Users can retrieve a list of available chat rooms (GET /api/chat/rooms).
Users can create new chat rooms (POST /api/chat/rooms) with a name and an optional description.
Users can retrieve details of a specific chat room (GET /api/chat/rooms/int:room_id), including its members and messages.

* **Sending Messages to Chat Rooms (POST /api/chat/rooms/int:room_id/messages)**
Authenticated users can send messages to a specific chat room.
Messages should be associated with the sender's user ID and the chat room ID.
Messages are broadcasted in real-time to all users in the chat room using WebSocket.

* **Retrieving Chat Room Messages (GET /api/chat/rooms/int:room_id/messages)**
Users can retrieve the message history of a specific chat room.
The history includes message content, sender information, and timestamps.

* **WebSocket Real-Time Chat**
WebSocket (via Flask-SocketIO) is used to enable real-time chat functionality.
Users must authenticate with a valid JWT token to send messages via WebSocket.
Messages sent via WebSocket are broadcasted to all users in the chat room in real-time.
#### Requirements

### Detail Design and Architecture
The application include sqlite database for development phase.
### Environment setup

#### **Step-1** Clone the repo

```
# git clone project
https://github.com/hamnawan/flask-chatapp
```
#### **Step-2** Python-vitual environment and dependencies installation

```
# create app-env python-virtual environment
python3 -m venv app-env

# to install the required packages
pip install -r requirements
```

#### **Step-3** Activate python-virtual environment (venv)
```
# 
source venc/bin/activate
```

#### **Run application
```

#run app
 pyhton main_app.py

```
 
