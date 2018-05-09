from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from binascii import unhexlify, hexlify #This resonsible about removing \x from the cipher text, we do it when sending the message

def generate_keys():
	#Generate a public/ private key pair using 2048 bits key length
	key = RSA.generate(2048)

	#password to open the private_key file... 	
	#if only exportKey('PEM') then it will save the private key in text encoding only which is plain text
	secret_code = "password" 

	#The private key in PEM format.. encrypted with Scrypt
	private_key = key.exportKey(format='PEM', passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")
	
	#store it in a file 
	f = open("private_key.pem", "wb")
	f.write(private_key)
	
	#The public key
	public_key = key.publickey().exportKey('PEM')
	f = open("public_key.pem", "wb")
	f.write(public_key)
	f.close()

#every user have a set of users' public key and we want to encrypt the message with specific key, so every user key stored with his name
def encrypt(username, msg):
	#get the reciever's public key
	f = open("{}.pem".format(username)) # a.salama.pem
	recipient_key = RSA.import_key(f.read())
	f.close()
	
	# Encrypt the session key with the reciever's public RSA key
	cipher_rsa = PKCS1_OAEP.new(recipient_key)

	# Encrypt the data with the AES session key
	session_key = get_random_bytes(16)	
	cipher_aes = AES.new(session_key, AES.MODE_EAX)
	ciphertext, tag = cipher_aes.encrypt_and_digest(msg)
	
	#finishing your processing
	encrypted_data = cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag +  ciphertext	
	encrypted_data = hexlify(encrypted_data).decode("utf-8")
	return encrypted_data	

def decrypt(enc_message):
	enc_message = unhexlify(enc_message)
	f = open('private_key.pem', 'r') #255 length
	secret_code = "password" #password to open the private_key file
	private_key = RSA.import_key(f.read(), passphrase=secret_code)
	f.close()
	
	#Read the pieces of the file 
	enc_session_key = enc_message[ 0 : private_key.size_in_bytes() ]
	nonce = enc_message[ private_key.size_in_bytes() : private_key.size_in_bytes() + 16 ]
	tag = enc_message[ private_key.size_in_bytes() + 16 : private_key.size_in_bytes() + 32 ]
	ciphertext = enc_message[ private_key.size_in_bytes() + 32 : ]
   
	# Decrypt the session key with the owner's private RSA key
	cipher_rsa = PKCS1_OAEP.new(private_key)
	session_key = cipher_rsa.decrypt(enc_session_key)

	# Decrypt the data with the AES session key
	cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
	msg = cipher_aes.decrypt_and_verify(ciphertext, tag)
	return msg.decode('utf-8')