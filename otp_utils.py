import os
import smtplib
import random
from email.mime.text import MIMEText
from flask_socketio import join_room, emit
from redis import Redis
from dotenv import load_dotenv
from socket_instance import socketio 



load_dotenv()

EMAIL = os.getenv("EMAIL_ADDRESS")
EMAIL_PASS = os.getenv("EMAIL_PASSWORD")
REDIS_URL = os.getenv("REDIS_URL")
redis = Redis.from_url(REDIS_URL)

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp(email: str, otp: str) -> bool:
    msg = MIMEText(f"Your OTP is: {otp}")
    msg["Subject"] = "Email OTP Verification"
    msg["From"] = EMAIL
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL, EMAIL_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print("Email send error:", e)
        return False


@socketio.on('join')
def on_join(data):
    user_id = data['userID']
    join_room(user_id)
    emit('joined', {'message': f'User {user_id} joined the chat room'}, room=user_id)

