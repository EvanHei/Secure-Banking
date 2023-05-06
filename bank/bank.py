import socket
from datetime import datetime
from random import random
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from OpenSSL import crypto

############# FUNCTIONS ###############
# accept a data string, encrypts, creates a digital signature, and sends it to the atm
def sendDataRsa(data):
	encryptedData = bankEncryptionCipher.encrypt(data.encode())
	digest = SHA256.new(data.encode())
	digSig = pkcs1_15.new(bankPrivateKey).sign(digest)
	print("\nCreated digest: " + str(digest))
	print("\nSending digital signature:\n" + str(digSig))
	print("\nSending encrypted data:\n" + str(encryptedData))
	atmSock.send(encryptedData)
	atmSock.send(digSig)

	
def sendDataDsa(data):
	encryptedData = bankEncryptionCipher.encrypt(data.encode())
	digSig = crypto.sign(bankDsaPrivateKey, data.encode(), 'sha256')
	print("\nSending digital signature:\n" + str(digSig))
	print("\nSending encrypted data:\n" + str(encryptedData))
	atmSock.send(encryptedData)
	atmSock.send(digSig)

	
# receives a data string and digital signature, decrypts, and validates signature. Returns decrypted data
def receiveDataRsa():
	encryptedData = atmSock.recv(1024)
	digSig = atmSock.recv(1024)
	decryptedData = bankDecryptionCipher.decrypt(encryptedData).decode('ascii')
	computedDigest = SHA256.new(decryptedData.encode())
	print("\nReceived digital signature:\n" + str(digSig))
	print("\nComputed digest:\n" + str(computedDigest))
	print("\nDecrypted data: " + decryptedData)
	try:
		pkcs1_15.new(atmPublicKey).verify(computedDigest, digSig)
		print("\nValid digital signature.")
	except (ValueError, TypeError):
		atmSock.close()
		print("Invalid digital signature, closing ATM connection.")
	return decryptedData


def receiveDataDsa():
	encryptedData = atmSock.recv(1024)
	digSig = atmSock.recv(1024)
	decryptedData = bankDecryptionCipher.decrypt(encryptedData).decode('ascii')
	print("\nReceived encrypted data:\n" + str(encryptedData))
	print("\nReceived digital signature:\n" + str(digSig))
	print("\nDecrypted data: " + str(decryptedData))
	try:
		crypto.verify(atmCertificate, digSig, decryptedData.encode(), 'sha256')
		print("Valid digital signature.")
	except:
		atmSock.close()
		print("Invalid digital signature, closing ATM connection.")
	return decryptedData


############# CRYPTOGRAPHIC TOOLS ###############
# key files
ATM1_RSA_PUBLIC_KEY_FILE_NAME = "atm1_rsa_public_key.pem"
ATM1_DSA_CERTIFICATE_FILE_NAME = "atm1_dsa_certificate.crt"
ATM2_RSA_PUBLIC_KEY_FILE_NAME = "atm2_rsa_public_key.pem"
ATM2_DSA_CERTIFICATE_FILE_NAME = "atm2_dsa_certificate.crt"
BANK_RSA_PRIVATE_KEY_FILE_NAME = "bank_rsa_private_key.pem"
BANK_DSA_PRIVATE_KEY_FILE_NAME = "bank_dsa_private.key"

# load RSA public/private keys
file = open(ATM1_RSA_PUBLIC_KEY_FILE_NAME)
atm1PublicKey = RSA.import_key(file.read())
file.close()

file = open(ATM2_RSA_PUBLIC_KEY_FILE_NAME)
atm2PublicKey = RSA.import_key(file.read())
file.close()

file = open(BANK_RSA_PRIVATE_KEY_FILE_NAME)
bankPrivateKey = RSA.import_key(file.read())
file.close()

# encryption/decryption ciphers
bankEncryptionCipherAtm1 = PKCS1_OAEP.new(atm1PublicKey, hashAlgo=None, mgfunc=None, randfunc=None)
bankEncryptionCipherAtm2 = PKCS1_OAEP.new(atm2PublicKey, hashAlgo=None, mgfunc=None, randfunc=None)
bankDecryptionCipher = PKCS1_OAEP.new(bankPrivateKey, hashAlgo=None, mgfunc=None, randfunc=None)

# load atm1's DSA certificate
file = open(ATM1_DSA_CERTIFICATE_FILE_NAME)
atm1CertificateBuffer = file.read()
file.close()
atm1Certificate = crypto.load_certificate(crypto.FILETYPE_PEM, atm1CertificateBuffer)

# load atm2's DSA certificate
file = open(ATM2_DSA_CERTIFICATE_FILE_NAME)
atm2CertificateBuffer = file.read()
file.close()
atm2Certificate = crypto.load_certificate(crypto.FILETYPE_PEM, atm2CertificateBuffer)

# load this bank's DSA private key
file = open(BANK_DSA_PRIVATE_KEY_FILE_NAME)
bankDsaPrivateKeyBuffer = file.read()
file.close()
bankDsaPrivateKey = crypto.load_privatekey(crypto.FILETYPE_PEM, bankDsaPrivateKeyBuffer)

############# USER INFORMATION ###############
# valid user info (username and password concatenated)
validUserCredentials = "123456password"
userHistory = []
userBalance = 0

############# NETWORK ##############
PORT_NUMBER = 1249
bankSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bankSock.bind(('', PORT_NUMBER))
bankSock.listen(100)


# accept ATM connections
while True:
	print("\nWaiting for ATMs to connect...")

	# Accept a waiting ATM connection
	atmSock, atmInfo = bankSock.accept()

	print("\n----------------- ATM AUTHENTICATION -----------------")
	# get the atm's ID, either "atm1" or "atm2"
	atmId = atmSock.recv(1024).decode('ascii')
	print("\nReceived ATM ID: " + atmId)
	
	# choose which cipher to use
	if atmId == "atm1":
		bankEncryptionCipher = bankEncryptionCipherAtm1
		atmPublicKey = atm1PublicKey
		atmCertificate = atm1Certificate
		validId = True
	elif atmId == "atm2":
		bankEncryptionCipher = bankEncryptionCipherAtm2
		atmPublicKey = atm2PublicKey
		atmCertificate = atm2Certificate
		validId = True
	else:
		validId = False
		atmSock.send("Invalid ID".encode())
		atmAuthenticated = False
		atmSock.close()
		print("\nFailed ATM authentication, closing ATM connection.")
		
	if validId:
		# send a nonce challenge encrypted with this bank's public key
		nonce = str(random())
		encryptedNonce = bankEncryptionCipher.encrypt(nonce.encode())
		atmSock.send(encryptedNonce)
		print("Plaintext challenge nonce: " + nonce)
		print("\nSending encrypted challenge nonce:\n" + str(encryptedNonce))
		
		# get the returned nonce and decrypt
		returnedNonce = atmSock.recv(1024)
		decryptedNonce = bankDecryptionCipher.decrypt(returnedNonce).decode('ascii')
		print("\nReceived encrypted returned nonce:\n" + str(returnedNonce))
		print("\nDecrypted returned nonce: " + decryptedNonce)
		
		if decryptedNonce == nonce:
			print("Successful ATM authentication.")
			atmAuthenticated = True
		else:
			print("Failed ATM authentication.")
			atmAuthenticated = False
		
		print("\n----------------- SINGING SCHEME -----------------")
		# get the chosen scheme
		signingChoice = int(atmSock.recv(1024).decode('ascii'))
		print("\nReceived signing choice: " + str(signingChoice))

		# choose RSA/DSA functions
		if signingChoice == 1:
			sendData = sendDataRsa
			receiveData = receiveDataRsa
			print("Using RSA scheme")
		elif signingChoice == 2:
			sendData = sendDataDsa
			receiveData = receiveDataDsa
			print("Using DSA scheme")
		
		print("\n----------------- USER CREDENTIAL VALIDATION -----------------")
		if atmAuthenticated == True:
			credentials = receiveData()

			# validate credentials
			if credentials == validUserCredentials:
				sendData("true")
				validCredentials = True
				print("\nSuccessful user credential validation.")
			else:
				sendData("false")
				validCredentials = False
				atmSock.close()
				print("\nFailed user credential validation, closing ATM connection.")

		print("\n----------------- TRANSACTION PROCESSING -----------------")
		if validCredentials and atmAuthenticated:
			runAgain = "Y"
			while runAgain.upper() == "Y":
				choice = receiveData()

				if int(choice) == 1: # display balance
					sendData(str(userBalance))
				elif int(choice) == 2: # deposit
					deposit = receiveData()

					# add to the balance and user history
					userBalance += int(deposit)
					userHistory.append("Deposit $" + deposit + " " + str(datetime.now()))
					print("New balance: " + str(userBalance))
					print("New account history: " + str(userHistory))
				elif int(choice) == 3:  # withdrawal
					withdrawal = receiveData()

					# subtract from the balance and add to user history
					userBalance -= int(withdrawal)
					userHistory.append("Withdrawal $" + withdrawal + " " + str(datetime.now()))
					print("New balance: " + str(userBalance))
					print("New account history: " + str(userHistory))
				elif int(choice) == 4: # display history
					sendData(str(userHistory))
				elif int(choice) == 5: # quit
					runAgain = "N"
					print("Quitting.")

				if int(choice) != 5:
					runAgain = receiveData()

		# Hang up the ATM's connection
		atmSock.close()
		print("\nClosing ATM connection.")
