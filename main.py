from Crypto.Cipher import AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random


def generate_keys(name1="user1", name2="user2"):
    # key generation
    privatekey = RSA.generate(2048)
    f = open(f'c:\cipher\\{name1}privatekey.txt', 'wb')
    f.write(bytes(privatekey.exportKey('PEM')));
    f.close()
    publickey = privatekey.publickey()
    f = open(f'c:\cipher\\{name1}publickey.txt', 'wb')
    f.write(bytes(publickey.exportKey('PEM')));
    f.close()
    privatekey = RSA.generate(2048)
    f = open(f'c:\cipher\\{name2}privatekey.txt', 'wb')
    f.write(bytes(privatekey.exportKey('PEM')));
    f.close()
    publickey = privatekey.publickey()
    f = open(f'c:\cipher\\{name2}publickey.txt', 'wb')
    f.write(bytes(publickey.exportKey('PEM')));
    f.close()

def create_signature(name1="user1", name2="user2", filename="plaintext.txt"):
    # creation of signature
    f = open(f'c:\cipher\{filename}','rb')
    plaintext = f.read(); f.close()
    privatekey = RSA.importKey(open(f'c:\cipher\\{name1}privatekey.txt','rb').read())
    myhash = SHA.new(plaintext)
    signature = PKCS1_v1_5.new(privatekey)
    signature = signature.sign(myhash)
    # signature encrypt
    publickey = RSA.importKey(open(f'c:\cipher\\{name2}publickey.txt','rb').read())
    cipherrsa = PKCS1_OAEP.new(publickey)
    sig = cipherrsa.encrypt(signature[:128])
    sig = sig + cipherrsa.encrypt(signature[128:])
    f = open('c:\cipher\signature.txt','wb')
    f.write(bytes(sig))
    f.close()

def create_session_256bit_key(name1="user2", filename="plaintext.txt"):
    # creation 256 bit session key
    sessionkey = Random.new().read(32)  # 256 bit
    # encryption AES of the message
    f = open(f'c:\cipher\{filename}', 'rb')
    plaintext = f.read()
    f.close()
    iv = Random.new().read(16)  # 128 bit
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    ciphertext = iv + obj.encrypt(plaintext)
    f = open(f'c:\cipher\{filename}', 'wb')
    f.write(bytes(ciphertext))
    f.close()
    # encryption RSA of the session key
    publickey = RSA.importKey(open(f'c:\cipher\\{name1}publickey.txt', 'rb').read())
    cipherrsa = PKCS1_OAEP.new(publickey)
    sessionkey = cipherrsa.encrypt(sessionkey)
    f = open('c:\cipher\sessionkey.txt', 'wb')
    f.write(bytes(sessionkey))
    f.close()

def decrypt_session_key(name1="user2", filename="plaintext.txt"):
    # decryption session key
    privatekey = RSA.importKey(open(f'c:\cipher\\{name1}privatekey.txt', 'rb').read())
    cipherrsa = PKCS1_OAEP.new(privatekey)
    f = open('c:\cipher\sessionkey.txt', 'rb')
    sessionkey = f.read()
    f.close()
    sessionkey = cipherrsa.decrypt(sessionkey)
    # decryption message
    f = open(f'c:\cipher\{filename}', 'rb')
    ciphertext = f.read()
    f.close()
    iv = ciphertext[:16]
    obj = AES.new(sessionkey, AES.MODE_CFB, iv)
    plaintext = obj.decrypt(ciphertext)
    plaintext = plaintext[16:]
    f = open(f'c:\cipher\{filename}', 'wb')
    f.write(bytes(plaintext))
    f.close()

def decryption_signature(name1="user1", name2="user2", filename="plaintext.txt"):
    # decryption signature
    f = open('c:\cipher\signature.txt','rb')
    signature = f.read(); f.close()
    privatekey = RSA.importKey(open(f'c:\cipher\\{name2}privatekey.txt','rb').read())
    cipherrsa = PKCS1_OAEP.new(privatekey)
    sig = cipherrsa.decrypt(signature[:256])
    sig = sig + cipherrsa.decrypt(signature[256:])
    # signature verification
    f = open(f'c:\cipher\{filename}','rb')
    plaintext = f.read(); f.close()
    publickey = RSA.importKey(open(f'c:\cipher\\{name1}publickey.txt','rb').read())
    myhash = SHA.new(plaintext)
    signature = PKCS1_v1_5.new(publickey)
    test = signature.verify(myhash, sig)
    return test

generate_keys()
create_signature()
create_session_256bit_key()
decrypt_session_key()
print(decryption_signature())