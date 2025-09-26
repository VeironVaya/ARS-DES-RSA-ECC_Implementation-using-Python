import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# AES functions
def aes_encrypt_decrypt(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = cipher.iv
    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher2.decrypt(ct), AES.block_size)
    return pt.decode()

# DES functions
def des_encrypt_decrypt(message, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ct = cipher.encrypt(pad(message.encode(), DES.block_size))
    iv = cipher.iv
    cipher2 = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher2.decrypt(ct), DES.block_size)
    return pt.decode()

# Test message
message = "HELLOCRYPTO" * 1000000 # make message longer for clearer timing difference

# AES timing
key_aes = get_random_bytes(16)  # AES-128
start_aes = time.time()
aes_encrypt_decrypt(message, key_aes)
end_aes = time.time()
aes_time = end_aes - start_aes

# DES timing
key_des = get_random_bytes(8)  # DES key size = 8 bytes
start_des = time.time()
des_encrypt_decrypt(message, key_des)
end_des = time.time()
des_time = end_des - start_des

print(f"AES execution time: {aes_time:.6f} seconds")
print(f"DES execution time: {des_time:.6f} seconds")
