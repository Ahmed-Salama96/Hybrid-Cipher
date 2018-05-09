import rsa

def print_private():
	fd = open("private_key.pem", "r")
	print(fd.read())
	print("\n\n")	
	fd.close()

def print_public():
	fd = open("public_key.pem", "r")
	print(fd.read())
	print("\n\n")
	fd.close()

#the plain text you want to cipher
plain_text = input("Enter plain text: ")
cipher_text = rsa.encrypt("public_key", plain_text.encode('utf-8'))
print("The ciphertext is: " + cipher_text)
print("\n")

#Return it to the original stat
plain_text = rsa.decrypt(cipher_text)
print("The plaintext again: " + plain_text)

rsa.generate_keys()
print_private()
print_public()