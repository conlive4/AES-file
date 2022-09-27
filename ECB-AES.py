
import sys
from Crypto.Cipher import AES
import binascii
import pyaes, pbkdf2, binascii, os
IV = 10
bs = AES.block_size

def encrypt(filename,password):
    input_file = open(filename, 'rb')
    output_file = open(filename + '.encrypted', 'wb')
    passwordSalt = b'\x02\x1d\xb6\x88\x19\xe2\xf0\xfc\x0ec\x97\xaaV\x92\x13\xfa'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    finished= False
    cipher =AES.new(key,AES.MODE_ECB)
    while not finished:
        chunk = input_file.read(1024*bs)
        if len(chunk) == 0 or len(chunk) % bs != 0:#final block/chunk is padded before encryption
            padding_length = (bs - len(chunk) % bs) or bs
            chunk += str.encode(padding_length * chr(padding_length))
            finished = True
        output_file.write(cipher.encrypt(chunk))
    print("Successfull!!!")           
    
def decrypt(filename,password):   
    input_file = open(filename + '.encrypted', 'rb')
    output_file = open(filename + '.decrypted', 'wb')
    passwordSalt = b'\x02\x1d\xb6\x88\x19\xe2\xf0\xfc\x0ec\x97\xaaV\x92\x13\xfa'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    cipher = AES.new(key, AES.MODE_ECB)
    next_chunk = ''
    finished = False
    while not finished:
        chunk, next_chunk = next_chunk, cipher.decrypt(input_file.read(1024 * bs))
        if len(next_chunk) == 0:
            padding_length = chunk[-1]
            chunk = chunk[:-padding_length]
            finished = True 
        output_file.write(bytes(x for x in chunk))
    print("Successfull!!!")
    

if __name__ == "__main__":
    # params
    args = sys.argv
    if len(args) < 4:
        print("python AESfile.py <choice: E/D> <filename> ")
        exit()
        
    choice = args[1]
    if choice.upper() not in ['E', 'D']:
        print("Choice must be E or D")
        exit()
    filename = args[2]
    password = args[3]
  
    # process
    #
    #print('AES encryption key:', binascii.hexlify(getKey))
    if choice.upper() == 'E':
        encrypt(filename,password)
    else: # choice == 'D'
        decrypt(filename,password)
