
from Crypto.PublicKey import RSA
import Crypto
from Crypto import Random
import binascii

def bin2hex(binStr):
    return binascii.hexlify(binStr)

def hex2bin(hexStr):
    return binascii.unhexlify(hexStr)

random_generator = Random.new().read
key = RSA.generate(1024, random_generator) #generate pub and priv key
binPrivKey = key.exportKey('DER')
binPubKey =  key.publickey().exportKey('DER')
print(bin2hex(binPrivKey))