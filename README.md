# Secure-Banking
This program allows a user to view their bank account balance, history, make deposits, and make withdrawls securely by using cryptographic techniques such as encryption, digital signatures, and authentication protocols.
## Requirements
The following libraries must be installed:

### Linux Ubuntu
    sudo pip install pycryptodomex
    sudo pip install pyopenssl
    sudo pip install pwinput

### Windows
    pip install pycryptodomex
    pip install pyopenssl
    pip install pwinput

## Instructions
Run the commands below in at least 2 terminal windows:

### Linux Ubuntu
    python3 bank.py
    python3 atm1.py
    python3 atm2.py

Enter "123456" for the valid user ID and "password" for the password.

### Windows
    python .\bank.py
    python .\atm1.py
    python .\atm2.py

Enter "123456" for the valid user ID and "password" for the password.

## Notes
All files other than the Python files and this README contain the public/private keys for the ATMs and bank. The bank only holds one account, and transaction history does not persist after server termination.
