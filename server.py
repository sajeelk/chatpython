"""Server for multithreaded (asynchronous) chat application."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from OpenSSL import SSL
import asymmetric
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

private_key = asymmetric.gen_private_key()
public_key = asymmetric.gen_public_key(private_key)

def accept_incoming_connections():
	"""Sets up handling for incoming clients."""
	while True:
		client, client_address = s.accept()
		print("%s:%s has connected." % client_address)
		client.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
		client_public_key = client.recv(BUFSIZ)
		cpublic_key = serialization.load_pem_public_key(client_public_key, backend=default_backend())
		addresses[client] = client_address
		Thread(target=handle_client, args=(client,cpublic_key,)).start()


def handle_client(client, cpublic_key):  # Takes client socket as argument.
	"""Handles a single client connection."""
	name = asymmetric.do_decrypt(client.recv(BUFSIZ), private_key).decode('utf8') 
	clients[client] = cpublic_key
	broadcast("%s has joined the chat!" % name)

	while True:
		msg = client.recv(BUFSIZ)
		msg = asymmetric.do_decrypt(msg, private_key)
		if msg != bytes("{quit}", "utf8"):
			broadcast(msg, name+": ")
		else:
			client.send(asymmetric.do_encrypt(bytes("{quit}", "utf8"), cpublic_key))
			client.close()
			del clients[client]
			broadcast("%s has left the chat." % name)
			break


def broadcast(msg, prefix=""):  # prefix is for name identification.
	"""Broadcasts a message to all the clients."""
	for client in clients:
		try:
			client.send((asymmetric.do_encrypt(bytes(prefix + msg.decode('utf8'), 'utf8'), clients[client])))
		except:
			client.send((asymmetric.do_encrypt(bytes(prefix + msg, 'utf8'), clients[client])))
# clients = {X's socket: X's public key, Y's socket: Y's public key}
clients = {}
addresses = {}

HOST = '127.0.0.1'
PORT = 33000
BUFSIZ = 1024
ADDR = (HOST, PORT)


context = SSL.Context(SSL.TLSv1_2_METHOD)
context.use_privatekey_file('key')
context.use_certificate_file('cert')

s = socket(AF_INET, SOCK_STREAM)
s = SSL.Connection(context, s)
s.bind(ADDR)

if __name__ == "__main__":
	s.listen(5)
	print("Waiting for connection...")
	ACCEPT_THREAD = Thread(target=accept_incoming_connections)
	ACCEPT_THREAD.start()
	ACCEPT_THREAD.join()
	s.close()
