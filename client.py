import socket
import os
import getpass
import pickle
import utils
import sys
from Crypto.Cipher import DES3

def getKeyPacket():
    generatedKey, secret = utils.generatePublicKey()
    packet = utils.Packet(utils.Header(utils.opcodeDict["PUBKEY"], socket.gethostname(), HOST), generatedKey, None, None, None, None)
    msgToSend = pickle.dumps(packet)
    msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
    return msgToSend, secret

def getSharedKey(secret):
    msg = sock.recv(utils.CLIENT_BUFFER_SIZE)
    msgLen = int(msg[:utils.HEADER_LENGTH])
    fullMsg = msg
    while len(fullMsg) < msgLen:
        msg = self.request.recv(utils.CLIENT_BUFFER_SIZE)
        fullMsg += msg
    msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
    print(f"Recieved:\nOpcode: {msgFromServer.header.opcode}, Prime: {msgFromServer.publicKey.prime}, Root: {msgFromServer.publicKey.root}, PubKey: {msgFromServer.publicKey.pub_key}")
    sharedKey = utils.generateFullKey(msgFromServer.publicKey, secret)
    return sharedKey

def sendFileReq(filename):
    packet = utils.Packet(utils.Header(utils.opcodeDict["REQSERV"], socket.gethostname(), HOST), None, utils.ReqServ(filename), None, None, None)
    msgToSend = pickle.dumps(packet)
    msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
    sock.sendall(msgToSend)

def getResponse(key, filename):
    msg = sock.recv(utils.CLIENT_BUFFER_SIZE)
    msgLen = int(msg[:utils.HEADER_LENGTH])
    fullMsg = msg
    while len(fullMsg) < msgLen:
        msg = sock.recv(utils.CLIENT_BUFFER_SIZE)
        fullMsg += msg
    # msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
    msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:utils.HEADER_LENGTH + msgLen])
    if msgFromServer.header.opcode == utils.opcodeDict["DISCONNECT"]:
        print("File not found at server")
        return
    if len(key) < utils.KEY_LENGTH:
        key = f"{key:<{utils.KEY_LENGTH}}"
    cipher = DES3.new(key)
    with open(utils.CLIENT_HOME + filename, "wb") as file:
        while msgFromServer.header.opcode != utils.opcodeDict["REQCOM"]:
            decrypted_data = cipher.decrypt(msgFromServer.encMsg.msg)
            file.write((decrypted_data)[:msgFromServer.encMsg.length])
            msg = fullMsg[utils.HEADER_LENGTH + msgLen:] + sock.recv(utils.CLIENT_BUFFER_SIZE)
            #msg = sock.recv(utils.CLIENT_BUFFER_SIZE)
            msgLen = int(msg[:utils.HEADER_LENGTH])
            fullMsg = msg
            while len(fullMsg) < msgLen:
                msg = sock.recv(utils.CLIENT_BUFFER_SIZE)
                fullMsg += msg
            # msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
            msgFromServer = pickle.loads(fullMsg[utils.HEADER_LENGTH:utils.HEADER_LENGTH + msgLen])
    print("file saved")

HOST, PORT = sys.argv[1], 9998
while True:
    os.system("clear")
    print("Key exchange initiated...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    msgToSend, secret1 = getKeyPacket()
    sock.sendall(msgToSend)
    sharedKey1 = getSharedKey(secret1)
    msgToSend, secret2 = getKeyPacket()
    sock.sendall(msgToSend)
    sharedKey2 = getSharedKey(secret2)
    msgToSend, secret3 = getKeyPacket()
    sock.sendall(msgToSend)
    sharedKey3 = getSharedKey(secret3)
    print(f"Shared keys: {sharedKey1}\n{sharedKey2}\n{sharedKey3}")
    print("Enter filename:")
    filename = input()
    sendFileReq(filename)
    getResponse(str(sharedKey1) + str(sharedKey2) + str(sharedKey3), filename)
    sock.shutdown(socket.SHUT_RDWR)
    getpass.getpass(prompt="")