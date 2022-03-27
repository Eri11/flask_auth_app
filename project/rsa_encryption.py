from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii

keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
#print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
#print(pubKeyPEM.decode('ascii'))

#print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
#print(privKeyPEM.decode('ascii'))


msg = b'V3ryG00dPassw0rd?!'

def encrypt(pubKey, msg):
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(msg)
    #print("Encrypted:", binascii.hexlify(encrypted))

    return encrypted

encryptedMsg = encrypt(pubKey, msg)
print(f'EncryptedMSG: {encryptedMsg}')


def decrypt (keyPair, encryptedMsg):
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(encryptedMsg)
    #print('Decrypted:', decrypted)

    return decrypted

decryptedMSG = decrypt(keyPair, encryptedMsg)
print(f'DecryptedMSG: {decryptedMSG}')