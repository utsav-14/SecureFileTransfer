from random import randint
import sympy
from math import gcd

class Header:
    def __init__(self, opcode, source_addr, dest_addr):
        self.opcode = opcode
        self.source_addr = source_addr
        self.dest_addr = dest_addr

class PublicKey:
    def __init__(self, prime, root, pub_key):
        self.prime = prime
        self.root = root
        self.pub_key = pub_key

class ReqServ:
    def __init__(self, filename):
        self.filename = filename

class ReqComp:
    def __init__(self, status):
        self.status = status

class EncodedMsg:
    def __init__(self, msg, length):
        self.msg = msg
        self.length = length

class Disconnect:
    def __init__(self):
        self.disconnectMsg = "See you soon!"

class Packet:
    def __init__(self, header, publicKey, reqServ, reqComp, encMsg, disconnect):
        self.header = header
        self.publicKey = publicKey
        self.reqServ = reqServ
        self.reqComp = reqComp
        self.encMsg = encMsg
        self.disconnect = disconnect

HEADER_LENGTH = 10
KEY_LENGTH = 24
SERVER_BUFFER_SIZE = 1024
CLIENT_BUFFER_SIZE = 1325
LOW_PRIME = 32768
HIGH_PRIME = 65536
CLIENT_HOME = "client/"
SERVER_HOME = "files/"

opcodeDict = {"PUBKEY":10, "REQSERV":20, "ENCMSG":30, "REQCOM":40, "DISCONNECT":50}

def generatePublicKey(publicKey = None):
    if publicKey == None:
        primeNo = sympy.randprime(LOW_PRIME, HIGH_PRIME)
        primitiveRoot = primitive_root(primeNo)
        publicKey = PublicKey(primeNo, primitiveRoot, None)
    secret = randint(1, publicKey.prime)
    return PublicKey(publicKey.prime, publicKey.root, pow(publicKey.root, secret, publicKey.prime)), secret

def generateFullKey(publicKey, secret):
    fullKey = pow(publicKey.pub_key, secret, publicKey.prime)
    return fullKey

def primitive_root(modulo):
    required_set = set(num for num in range (1, modulo) if gcd(num, modulo) == 1)
    for g in range(1, modulo):
        actual_set = set(pow(g, powers, modulo) for powers in range (1, modulo))
        if required_set == actual_set:
            return g