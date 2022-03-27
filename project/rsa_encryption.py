from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

keyPair = RSA.generate(3072)

pubKey = keyPair.publickey()
#print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
#print(pubKeyPEM.decode('ascii'))

#print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
#print(privKeyPEM.decode('ascii'))


password = 'V3ryG00dPassw0rd?!'

def encrypt(pubKey, password):
    stringToBytes = password.encode('utf-8')
    encryptor = PKCS1_OAEP.new(pubKey)
    encrypted = encryptor.encrypt(stringToBytes)
    #print("Encrypted:", binascii.hexlify(encrypted))

    return encrypted

encryptedPass = encrypt(pubKey, password)
print(f'EncryptedPWD: {encryptedPass}')


def decrypt (keyPair, encryptedPass):
    decryptor = PKCS1_OAEP.new(keyPair)
    decrypted = decryptor.decrypt(encryptedPass).decode('utf-8')
    #print('Decrypted:', decrypted)

    return decrypted

decryptedMSG = decrypt(keyPair, encryptedPass)
print(f'DecryptedPWD: {decryptedMSG}')