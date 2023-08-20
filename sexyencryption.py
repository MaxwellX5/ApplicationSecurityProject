import uuid
import os
import boto3
import base64
from cryptography.fernet import Fernet
from dotenv import load_dotenv
load_dotenv()

# key = Fernet.generate_key()
KEY = os.getenv('FERNET')
def encrypt(string):
    key = KEY
    fernet = Fernet(key)
    encrypted = fernet.encrypt(string.encode())
    return encrypted.decode()


def decrypt(ciphertext:bytes):
    if isinstance(ciphertext, str):
        ciphertext = ciphertext.encode()
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext are not in bytes")
    key = KEY
    fernet = Fernet(key)

    decrypted = fernet.decrypt(ciphertext)
    return decrypted.decode()


