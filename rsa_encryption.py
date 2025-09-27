from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Generate keys
priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub = priv.public_key()

# Encrypt (OAEP)
plaintext = b"testing RSA"
print("=== Plaintext ===")
print(plaintext)

ciphertext = pub.encrypt(
    plaintext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("=== Ciphertext ===")
print(ciphertext)

# Decrypt
decrypted = priv.decrypt(
    ciphertext,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
)
print("Decrypted text:", decrypted)
print("=== Decrypted text ===")
print(decrypted)
