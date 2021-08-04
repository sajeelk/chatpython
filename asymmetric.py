from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


def gen_private_key():
	return rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
def gen_public_key(private_key):
	return private_key.public_key()


def do_encrypt(message, public_key):
	return public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
def do_decrypt(ciphertext, private_key):
	return private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))
