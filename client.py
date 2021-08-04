"""Script for Tkinter GUI chat client."""
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
import tkinter, ssl, os, getpass
import asymmetric, symmetric
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from passlib.hash import pbkdf2_sha256


private_key = asymmetric.gen_private_key()
public_key = asymmetric.gen_public_key(private_key)

def receive():
	"""Handles receiving of messages."""
	while True:
		try:
			msg = client_socket.recv(BUFSIZ)#.decode("utf8")
			msg_list.insert(tkinter.END, asymmetric.do_decrypt(msg, private_key))
			with open('messages_%s.txt' % chatname, 'ab') as msgf:
				msgf.write(symmetric.do_encrypt(bytes(inpass, 'utf8'), asymmetric.do_decrypt(msg, private_key), salt) + "\n".encode('utf8'))
		except OSError:  # Possibly client has left the chat.
			break


def send(event=None):  # event is passed by binders.
	"""Handles sending of messages."""
	msg = my_msg.get()
	my_msg.set("")  # Clears input field.
	client_socket.send(asymmetric.do_encrypt(msg.encode('utf8'), spublic_key))
	if msg == "{quit}":
		client_socket.close()
		top.quit()


def on_closing(event=None):
	"""This function is to be called when the window is closed."""
	my_msg.set("{quit}")
	send()

top = tkinter.Tk()
top.title("Secure Chatter")

messages_frame = tkinter.Frame(top)
my_msg = tkinter.StringVar()  # For the messages to be sent.
# my_msg.set("Type your messages here.")
scrollbar = tkinter.Scrollbar(messages_frame)  # To navigate through past messages.
# Following will contain the messages.
msg_list = tkinter.Listbox(messages_frame, height=15, width=50, yscrollcommand=scrollbar.set)
scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
msg_list.pack()
messages_frame.pack()

entry_field = tkinter.Entry(top, textvariable=my_msg)
entry_field.bind("<Return>", send)
entry_field.pack()
send_button = tkinter.Button(top, text="Send", command=send)
send_button.pack()

top.protocol("WM_DELETE_WINDOW", on_closing)

if input('Would you like to create a new chat? (y/n) ').lower() == 'y':
	chatname = input("What would you like to name this chat? ")
	with open('messages_%s.txt' % chatname, 'w') as msgf:
		pass
	inpass = getpass.getpass("Enter a password: ")
	while getpass.getpass("Confirm a password: ") != inpass:
		inpass = input("Enter a password: ")
	with open('hash_%s.txt' % chatname, 'w') as hashf:
		hashf.write((pbkdf2_sha256.hash(inpass)))
	with open('salt_%s.txt' % chatname, 'wb') as saltf:
		salt = os.urandom(16)
		saltf.write(salt)
else:
	chatname = input("What is the name of the chat? ")
	inpass = getpass.getpass("Enter your password: ")
	with open('hash_%s.txt' % chatname, 'r') as hashf:
		thishash = hashf.read()
	with open('salt_%s.txt' % chatname, 'rb') as saltf:
		salt = saltf.read()
	while not pbkdf2_sha256.verify(inpass, thishash):
		inpass = getpass.getpass("Enter your password: ")
	with open('messages_%s.txt' % chatname, 'rb') as msgf:
		for msg in msgf.readlines():
			msg_list.insert(tkinter.END, symmetric.do_decrypt(inpass.encode('utf8'), msg, salt))





#----Now comes the sockets part----
# HOST = input('Enter host: ')
# PORT = input('Enter port: ')
# if not PORT:
# 	PORT = 33000
# else:
# 	PORT = int(PORT)

BUFSIZ = 1024
ADDR = ("127.0.0.1", 33000)

client_socket = socket(AF_INET, SOCK_STREAM)
client_socket = ssl.wrap_socket(client_socket)
client_socket.connect(ADDR)

client_socket.send(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

serv_public_key = client_socket.recv(BUFSIZ)
spublic_key = serialization.load_pem_public_key(serv_public_key, backend=default_backend())
client_socket.send(asymmetric.do_encrypt((input("Enter a username: ")).encode('utf8'), spublic_key))
print('Connected!')
receive_thread = Thread(target=receive)
receive_thread.start()
tkinter.mainloop()  # Starts GUI execution.
