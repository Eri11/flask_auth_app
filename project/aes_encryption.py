import base64
from pydoc import plain 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


key = 'mysecretpassword'.encode('utf-8')
iv = 'myivsupersecreta'.encode('utf-8')
password = 'password'

def encrypt(password, key, iv):
    passToByte = password.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(passToByte, AES.block_size))

    return ciphertext

encryptedPass = encrypt(password, key, iv)
print(f'Encrypted PWD: {encryptedPass}')


###

def decrypt(encryptedPass, key, iv):

    cipher =  AES.new(key, AES.MODE_CBC, iv)
    password = unpad(cipher.decrypt(encryptedPass), AES.block_size)
    decipherPass = password.decode('utf-8')

    return decipherPass

decryptedPass = decrypt(encryptedPass, key, iv)
print(f'Decrypted PWD: {decryptedPass}')