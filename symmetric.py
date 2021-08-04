import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def do_encrypt(password, plaintext, salt):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password))
	f = Fernet(key)
	return f.encrypt(plaintext)

def do_decrypt(password, ciphertext, salt):
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
	key = base64.urlsafe_b64encode(kdf.derive(password))
	f = Fernet(key)
	return f.decrypt(ciphertext)
