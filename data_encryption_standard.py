from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    return cipher.iv + ct_bytes  

def des_decrypt(ciphertext, key):
    iv = ciphertext[:DES.block_size]
    ct = ciphertext[DES.block_size:]
    print("blocksize:",DES.block_size)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct), DES.block_size)
    return decrypted.decode()

key = get_random_bytes(8)  
message = "HELLO"

ciphertext = des_encrypt(message, key)
decrypted_message = des_decrypt(ciphertext, key)

print("DES - Key (hex):", key.hex())
print("DES - Encrypted (hex):", ciphertext.hex())
print("DES - Decrypted:", decrypted_message)
