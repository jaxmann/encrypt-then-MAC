from Crypto.Cipher import AES
#pip install pycrypto
from Crypto.Protocol.KDF import PBKDF2
import hmac
import os

def encrypt(my_key,iv, message):

    K1 = my_key[0:16] # part 1 of the key, for encryption
    K2 = my_key[16:] # part 2 of the key, for authentication

    encryption_suite = AES.new(K1, AES.MODE_CBC, iv) # set up encryption with AES CBC mode with random IV suite
    ciphertext = encryption_suite.encrypt(message) #encrypt message

    tag = hmac.new(K2, msg=ciphertext).digest() # Return the digest of the strings passed to the update() method so far.

    return ciphertext + tag # concatenate ciphertext and tag together

def decrypt(my_key,ciphertext,iv,T):

    K1 = my_key[0:16] # part 1 of the key, for encryption
    K2 = my_key[16:] # part 2 of the key, for authentication

    decryption_suite = AES.new(K1, AES.MODE_CBC, iv)
    plain_text = decryption_suite.decrypt(ciphertext)

    tag = hmac.new(K2, msg=C).digest() # Return the digest of the strings passed to the update() method so far.

    if tag == T: # if tag generated is same as tag received, message is authentic
        return plain_text
    elif (tag != T): # if tag generated differs from tag received, message is not authentic and return contradiction
        return None

if __name__ == "__main__":

    salt = os.urandom(8)  # 64-bit salt - "Return a string of size random bytes suitable for cryptographic use."

    # Derive one or more keys from a password (or passphrase).
    # This performs key derivation according to the PKCS#5 standard (v2.0), by means of the PBKDF2 algorithm.
    my_key = PBKDF2("This passphrase is a secret.", salt, 32)  # 256-bit key - PBKDF2(password, salt, dkLen=16, count=1000, prf=None)

    iv = os.urandom(16)  # 128-bit IV

    message = 'x marks the spot'

    CT = encrypt(my_key,iv,message); # returns ciphertext concatenated with tag from MAC

    C = CT[0:16] #ciphertext
    T = CT[16:] #tag

    M = decrypt(my_key,C,iv,T) # returns message if valid key and tag, otherwise returns 'None'

    print M # print the original message

    print message == M # original equal to output?




