# Secure-Banking
This program allows a user to view their bank account balance, history, make desposits, and make withdrawls securely by using cryptographic techniques such as encryption, digital signatures, and authentication protocols.
## Requirements
The following libraries must be installed:

### Linux Ubuntu
* sudo pip install pycryptodomex
* sudo pip install pyopenssl
* sudo pip install pwinput

### Windows
* pip install pycryptodomex
* pip install pyopenssl
* pip install pwinput

## Instructions
Run the commands below in a terminal:

### Linux Ubuntu
1. python3 bank.py - start the bank server

2. python3 atm1.py - connect with ATM 1

3. python3 atm2.py - connect with ATM 2

Enter "123456" for the valid user ID and "password" for the password.


### Windows
1. python .\bank.py - start the bank server

2. python .\atm1.py - connect with ATM 1

3. python .\atm2.py - connect with ATM 2

Enter "123456" for the valid user ID and "password" for the password.


## Notes
All files other than the Python files and this README contain the public/private keys for the ATMs and bank. The bank only holds one account, and transaction history does not persist after server termination.
