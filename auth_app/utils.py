import random
import jwt
from datetime import datetime, timedelta
from django.core.mail import send_mail
from django.conf import settings
import random


def generate_otp():
    return str(random.randint(100000, 999999))


def send_sms_otp(phone, otp):
    """Fake OTP sender for testing (prints to console)"""
    print(f"Sending OTP to {phone}: {otp}")

def generate_jwt_token(user):
    payload = {
        'id': user.id,
        'username': user.username,
        'role': user.role,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    token = jwt.encode(payload, 'your-secret-key', algorithm='HS256')
    return token

