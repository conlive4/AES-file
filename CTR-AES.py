import pyaes, pbkdf2, binascii, os, secrets
import sys

def encrypt(key, IV, filename):
    plaintext = open(filename, encoding='utf8').read()
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(IV))
    ciphertext = aes.encrypt(plaintext)
    print('Encrypted:', binascii.hexlify(ciphertext))
    output_file = filename.replace('.txt', '_encrypt.txt')
    with open(output_file, 'wb') as f:
        f.write(ciphertext)
    print('Saved in', output_file)

def decrypt(key, IV, filename):
    aes = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(IV))
    byteStr = open(filename).read()
    ciphertext = byteStr.encode()
    decrypted = aes.decrypt(ciphertext)
    print('Decrypted:', decrypted)
    output_file = filename.replace('.txt', '_decrypt.txt')
    with open(output_file, 'wb') as f:
        f.write(decrypted)
    print('Saved in', output_file)

def getKey(password):
    # passwordSalt = os.urandom(16)
    passwordSalt = b'\x02\x1d\xb6\x88\x19\xe2\xf0\xfc\x0ec\x97\xaaV\x92\x13\xfa'
    key = pbkdf2.PBKDF2(password, passwordSalt).read(32)
    return key

if __name__ == "__main__":
    # params
    args = sys.argv
    if len(args) < 4:
        print("python AESfile.py <choice: E/D> <filename> <password>")
        exit()
        
    choice = args[1]
    if choice.upper() not in ['E', 'D']:
        print("Choice must be E or D")
        exit()
    filename = args[2]
    password = args[3]
  
    # process
    IV = 10
    key = getKey(password)
    print('AES encryption key:', binascii.hexlify(key))
    if choice.upper() == 'E':
        encrypt(key, IV, filename)
    else: # choice == 'D'
        decrypt(key, IV, filename)