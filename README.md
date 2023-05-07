# Secure-Banking
This program allows a user to view their bank account balance, history, make desposits, and make withdrawls securely by using cryptographic techniques such as encryption, digital signatures, and authentication protocols.
## Requirements
The following libraries must be installed:

### Linux Ubuntu
* sudo pip install pycryptodomex
* sudo pip install pyopenssl

### Windows
* pip install pycryptodomex
* pip install pyopenssl

## Instructions
### Linux Ubuntu
python3 bank.py - start the bank server

python3 atm1.py - connect with ATM 1

python3 atm2.py - connect with ATM 2

Enter "123456" for the valid user ID and "password" for the password.


### Windows
python .\bank.py - start the bank server

python .\atm1.py - connect with ATM 1

python .\atm2.py - connect with ATM 2

Enter "123456" for the valid user ID and "password" for the password.


## Notes
All files other than the Python files and this README contain the public/private keys for the ATMs and bank. The bank only holds one account, and transaction history does not persist after server termination.
