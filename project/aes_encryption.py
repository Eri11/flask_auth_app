import base64
from email.mime import base
from pydoc import plain 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


key = 'mysecretpassword'.encode('utf-8')
iv = 'myivsupersecreta'.encode('utf-8')
password = 'V3ryG00dPassw0rd?!'

def encrypt(password, key, iv):
    stringToBytes = pad(password.encode('utf-8'), AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64encode(cipher.encrypt(stringToBytes))

    return ciphertext

encryptedPass = encrypt(password, key, iv)
print(f'Encrypted PWD: {encryptedPass}')


###

def decrypt(encryptedPass, key, iv):
    #decodedPass = base64.b64decode(encryptedPass)
    #print(f'Decoded {decodedPass}')
    #decipher = AES.new(key, AES.MODE_CBC, iv)
    
    #deciphertext = decipher.decrypt(decodedPass)
    #print(f'Deciphered {deciphertext}')

    #unpadPass = unpad(deciphertext, AES.block_size)
    #print(f'Unpadded {unpadPass}')

    #bytesToString = unpadPass.decode('utf-8')
    
    #return decipherPass

    ###
    decodedPass = base64.b64decode(encryptedPass)
    print(f'Decoded {decodedPass}')

    decipher = AES.new(key, AES.MODE_CBC, iv)
    deciphertext = unpad(decipher.decrypt(decodedPass), AES.block_size).decode('utf-8')

    print(f'Unpadded, deciphered and to string {deciphertext}')
    
    return deciphertext

    

#decryptedPass = decrypt(encryptedPass, key, iv)
#print(f'Decrypted PWD: {decryptedPass}')

deciphered = decrypt(encryptedPass, key, iv)
print(f'Decrypted {deciphered}')