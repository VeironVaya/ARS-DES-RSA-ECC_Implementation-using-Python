from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext.encode())
    return encrypted

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

message = "HELLO"
ciphertext = rsa_encrypt(message, public_key)
decrypted_message = rsa_decrypt(ciphertext, private_key)

print("RSA - Encrypted:", ciphertext)
print("")
print("RSA - Decrypted:", decrypted_message)

