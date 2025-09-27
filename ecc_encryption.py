from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

# Generate private keys for Alice & Bob
priv_a = ec.generate_private_key(ec.SECP256R1())
priv_b = ec.generate_private_key(ec.SECP256R1())

pub_a = priv_a.public_key()
pub_b = priv_b.public_key()

print("=== Public Key Alice ===")
print(pub_a.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

print("=== Public Key Bob ===")
print(pub_b.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode())

# ECDH shared secret
shared_a = priv_a.exchange(ec.ECDH(), pub_b)
shared_b = priv_b.exchange(ec.ECDH(), pub_a)
assert shared_a == shared_b

print("=== Shared Secret (Alice & Bob) ===")
print(shared_a.hex()) 

# Derive symmetric key
derived_key = HKDF(
    algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data'
).derive(shared_a)

# Use AES-GCM for message encryption
aesgcm = AESGCM(derived_key)
nonce = urandom(12)
plaintext = b"testing ECC"
ct = aesgcm.encrypt(nonce, plaintext, None)
pt = aesgcm.decrypt(nonce, ct, None)

print("=== Plaintext ===")
print(plaintext)

print("=== Ciphertext ===")
print(ct.hex())

print("=== Decrypted Text ===")
print(pt)
