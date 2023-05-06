import socket
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Hash import SHA256
from OpenSSL import crypto

############# FUNCTIONS ###############
# accept a data string, encrypts, creates a digital signature, and sends it to the bank
def sendDataRsa(data):
	encryptedData = encryptionCipher.encrypt(data.encode())
	digest = SHA256.new(data.encode())
	digSig = pkcs1_15.new(atmPrivateKey).sign(digest)
	atmSock.send(encryptedData)
	atmSock.send(digSig)


def sendDataDsa(data):
	encryptedData = encryptionCipher.encrypt(data.encode())
	digSig = crypto.sign(atmDsaPrivateKey, data.encode(), 'sha256')
	atmSock.send(encryptedData)
	atmSock.send(digSig)

	
# receives a data string and digital signature, decrypts, and validates signature. Returns decrypted data
def receiveDataRsa():
	encryptedData = atmSock.recv(1024)
	digSig = atmSock.recv(1024)
	decryptedData = decryptionCipher.decrypt(encryptedData).decode('ascii')
	computedDigest = SHA256.new(decryptedData.encode())
	try:
		pkcs1_15.new(bankPublicKey).verify(computedDigest, digSig)
	except (ValueError, TypeError):
		atmSock.close()
		print("Invalid digital signature, closing ATM connection.")
	return decryptedData


def receiveDataDsa():
	encryptedData = atmSock.recv(1024)
	digSig = atmSock.recv(1024)
	decryptedData = decryptionCipher.decrypt(encryptedData).decode('ascii')
	try:
		crypto.verify(bankCertificate, digSig, decryptedData.encode(), 'sha256')
	except:
		atmSock.close()
		print("Invalid digital signature, closing ATM connection.")
	return decryptedData


############# CRYPTOGRAPHIC TOOLS ###############
# key files
BANK_RSA_PUBLIC_KEY_FILE_NAME = "bank_rsa_public_key.pem"
BANK_DSA_CERTIFICATE_FILE_NAME = "bank_dsa_certificate.crt"
ATM1_RSA_PRIVATE_KEY_FILE_NAME = "atm1_rsa_private_key.pem"
ATM1_DSA_PRIVATE_KEY_FILE_NAME = "atm1_dsa_private.key"

# load RSA public/private keys
file = open(BANK_RSA_PUBLIC_KEY_FILE_NAME)
bankPublicKey = RSA.import_key(file.read())
file.close()

file = open(ATM1_RSA_PRIVATE_KEY_FILE_NAME)
atmPrivateKey = RSA.import_key(file.read())
file.close()

# encryption/decryption ciphers
encryptionCipher = PKCS1_OAEP.new(bankPublicKey, hashAlgo=None, mgfunc=None, randfunc=None)
decryptionCipher = PKCS1_OAEP.new(atmPrivateKey, hashAlgo=None, mgfunc=None, randfunc=None)

# load bank's DSA certificate and this atm1's DSA private key
file = open(BANK_DSA_CERTIFICATE_FILE_NAME)
bankCertificateBuffer = file.read()
file.close()
bankCertificate = crypto.load_certificate(crypto.FILETYPE_PEM, bankCertificateBuffer)

file = open(ATM1_DSA_PRIVATE_KEY_FILE_NAME)
atmDsaPrivateKeyBuffer = file.read()
file.close()
atmDsaPrivateKey = crypto.load_privatekey(crypto.FILETYPE_PEM, atmDsaPrivateKeyBuffer)

############# NETWORK ###############
# Bank info
BANK_IP = "127.0.0.1"
BANK_PORT = 1249

# ATM socket
atmSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
atmSock.connect((BANK_IP, BANK_PORT))

############# ATM AUTHENTICATION ###############
# send ID of this atm1
atmSock.send("atm1".encode())

# receive the encrypted nonce, decrypt, re-encrypt, and send it back
encryptedNonce = atmSock.recv(1024)
nonce = decryptionCipher.decrypt(encryptedNonce)
reEncryptedNonce = encryptionCipher.encrypt(nonce)
atmSock.send(reEncryptedNonce)

############# SIGNING SCHEME ###############
# choose a DSA or RSA signing schema
signingChoice = int(input("1. RSA\n2. DSA\nChoose a digital signature scheme: "))

# validate input
while signingChoice not in range(1, 3):
	signingChoice = int(input("Please enter a valid choice: "))

# send choice
print("Sending choice: " + str(signingChoice))
atmSock.send(str(signingChoice).encode())

# choose RSA/DSA functions
if signingChoice == 1:
	sendData = sendDataRsa
	receiveData = receiveDataRsa
elif signingChoice == 2:
	sendData = sendDataDsa
	receiveData = receiveDataDsa

############# USER CREDENTIAL VALIDATION ###############
# get credentials
userId = input("ID: ")
password = input("Password: ")
userCredentials = userId + password
sendData(userCredentials)

# Receive bank message. Will be "true" if credentials were valid
bankMsg = receiveData()
if bankMsg == "true":
	runAgain = "Y"
else:
	print("Invalid credentials.")
	runAgain = "N"

############# TRANSACTION PROCESSING ###############
while runAgain.upper() == "Y":
	print('''
1. Display Account Balance
2. Make a Deposit
3. Make a Withdrawal
4. Display Transaction History
5. Quit''')
	choice = input("Enter your choice: ")
	# validate input
	while int(choice) not in range(1, 6):
		choice = input("Please enter a valid choice: ")
	sendData(choice)
		
	if int(choice) == 1:  # display balance
		balance = receiveData()
		print("Balance: " + balance)
	elif int(choice) == 2:  # deposit
		deposit = input("How much would you like to deposit? ")
		sendData(deposit)
	elif int(choice) == 3:  # Withdrawal
		withdrawal = input("How much would you like to withdraw? ")
		sendData(withdrawal)
	elif int(choice) == 4:  # display history
		userHistory = receiveData()
		print("User history: " + userHistory)
	elif int(choice) == 5:  # quit
		print("Goodbye!")
		runAgain = "N"

	if int(choice) != 5:
		runAgain = input("Run again? (Y/N): ")
		sendData(runAgain)
