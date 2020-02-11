## Secure file Transfer
### Description: 
A client-server application that securely shares files between clients and server using DES3 encryption mechanism.

### How to run:
### 1) Install dependencies:
* Crypto: Run "pip3 install Crypto"
* sympy: Run "pip3 intstall sympy"

### 2) Run the project
* Make a directory named "files" in the same directory where server.py resides and put files in it that you want to share with clients
* Make a separate directory for each client and make a directory named "downloads" in each of them
* Run server.py by typing "python3 server.py"
* Run each client from its respective directory using "python3 client.py 127.0.0.1"
* From client, enter the name of the file you want to download when prompted (the file should be present in server's "files" directory)


