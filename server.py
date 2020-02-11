import socket
import threading
import socketserver
import pickle
import utils
import os
from Crypto.Cipher import DES3

class ThreadedTCPRequestHandler(socketserver.BaseRequestHandler):

    def getSharedKey(self):
        msg = self.request.recv(utils.SERVER_BUFFER_SIZE)
        msgLen = int(msg[:utils.HEADER_LENGTH])
        fullMsg = msg
        while len(fullMsg) < msgLen:
            msg = self.request.recv(utils.SERVER_BUFFER_SIZE)
            fullMsg += msg
        msgFromClient = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
        serverPublicKey, secret = utils.generatePublicKey(msgFromClient.publicKey)
        sharedKey = utils.generateFullKey(msgFromClient.publicKey, secret)
        print(f"msgLength: {msgLen}, opcode: {msgFromClient.header.opcode}, prime: {msgFromClient.publicKey.prime}, root: {msgFromClient.publicKey.root}, publicKey: {msgFromClient.publicKey.pub_key}, secret: {secret}, \nShared Key: {sharedKey}")
        packet = utils.Packet(utils.Header(utils.opcodeDict["PUBKEY"], socket.gethostname(), HOST), serverPublicKey, None, None, None, None) 
        msgToSend = pickle.dumps(packet)
        msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
        self.request.sendall(msgToSend)
        print("Sent public key")
        return sharedKey

    def serveRequest(self, key):
        if len(key) < utils.KEY_LENGTH:
            key = f"{key:<{utils.KEY_LENGTH}}"
        msg = self.request.recv(utils.SERVER_BUFFER_SIZE)
        msgLen = int(msg[:utils.HEADER_LENGTH])
        fullMsg = msg
        while len(fullMsg) < msgLen:
            msg = self.request.recv(utils.SERVER_BUFFER_SIZE)
            fullMsg += msg
        msgFromClient = pickle.loads(fullMsg[utils.HEADER_LENGTH:])
        filename = msgFromClient.reqServ.filename
        print(f"Requested file: {filename} ", end = "")
        try:
            filepath = utils.SERVER_HOME + filename
            with open(filepath, "rb") as file:
                fileInfo = os.stat(filepath)
                fileSize = fileInfo.st_size
                print(fileSize, "bytes.")
                data = file.read(utils.SERVER_BUFFER_SIZE)
                cipher = DES3.new(key)
                while len(data) > 0 :
                    blockLength = len(data)
                    rem = blockLength % utils.SERVER_BUFFER_SIZE
                    if rem:
                        data += bytes(utils.SERVER_BUFFER_SIZE - rem)
                    encrypted_text = cipher.encrypt(data)
                    packet = utils.Packet(utils.Header(utils.opcodeDict["ENCMSG"], socket.gethostname(), HOST), None, None, None, utils.EncodedMsg(encrypted_text, blockLength), None) 
                    msgToSend = pickle.dumps(packet)
                    msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
                    self.request.sendall(msgToSend)
                    data = file.read(utils.SERVER_BUFFER_SIZE)
            packet = utils.Packet(utils.Header(utils.opcodeDict["REQCOM"], socket.gethostname(), HOST), None, None, utils.ReqComp(400), None, None) 
            msgToSend = pickle.dumps(packet)
            msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
            self.request.sendall(msgToSend)
            print("File sent")
        except FileNotFoundError:
            print("File not found")
            packet = utils.Packet(utils.Header(utils.opcodeDict["DISCONNECT"], socket.gethostname(), HOST), None, None, None, None, utils.Disconnect()) 
            msgToSend = pickle.dumps(packet)
            msgToSend = bytes(f"{len(msgToSend):<{utils.HEADER_LENGTH}}", "ascii") + msgToSend
            self.request.sendall(msgToSend)

    def handle(self):
        sharedKey1 = self.getSharedKey()
        sharedKey2 = self.getSharedKey()
        sharedKey3 = self.getSharedKey()
        print(f"shared keys:\n{sharedKey1}\n{sharedKey2}\n{sharedKey3}")
        self.serveRequest(str(sharedKey1) + str(sharedKey2) + str(sharedKey3))

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):pass

HOST, PORT = "127.0.0.1", 9998
server = ThreadedTCPServer((HOST, PORT), ThreadedTCPRequestHandler)
print(f"Server started...")
server.serve_forever()
