import os, random
from Crypto.Util.number import bytes_to_long, getPrime, isPrime
from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256

generate_secure_number = lambda: bytes_to_long(os.urandom(16))
def calculate_shared_variables():
    q = getPrime(256)
    p = 100
    while not isPrime(p):
        r = generate_secure_number()
        p = q*r+1

    return (p, pow(generate_secure_number(), r, p))


def generate_keys(g,p,connection):
    private = generate_secure_number()
    public = pow(g,private,p)

    connection.send(str(public).encode("ascii"))
    print(f"Generated private key: {private}")
    return private

def receive_public_key(connection):
    public_key = int(connection.recv(4096).decode("ascii"))
    print(f"Received public key: {public_key}")
    return public_key

def cipher_message(key, connection, message=None):
    nonce = os.urandom(12) if message else connection.recv(12)
    hmac_key = os.urandom(16) if message else connection.recv(16)

    cryptor = ChaCha20.new(key=HMAC.new(hmac_key, key, SHA256).digest(), nonce=nonce)
    if message:
        connection.send(nonce)
        connection.send(hmac_key)
        connection.send(cryptor.encrypt(message.encode("ascii")))
    else:
        return cryptor.decrypt(connection.recv(4096)).decode("ascii")