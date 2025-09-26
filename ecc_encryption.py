from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate ECC key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

def ecc_encrypt(plaintext, public_key):
    # Generate ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    # Encrypt with AES-GCM
    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return {
        "ciphertext": ciphertext,
        "tag": encryptor.tag,
        "iv": iv,
        "ephemeral_pub": ephemeral_key.public_key()
    }

def ecc_decrypt(enc_dict, private_key):
    # Recreate shared secret
    shared_secret = private_key.exchange(ec.ECDH(), enc_dict["ephemeral_pub"])

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"handshake data",
    ).derive(shared_secret)

    # Decrypt with AES-GCM
    decryptor = Cipher(
        algorithms.AES(derived_key),
        modes.GCM(enc_dict["iv"], enc_dict["tag"]),
        backend=default_backend()
    ).decryptor()

    plaintext = decryptor.update(enc_dict["ciphertext"]) + decryptor.finalize()
    return plaintext.decode()

# Example usage
message = "HELLO"
encrypted = ecc_encrypt(message, public_key)
decrypted_message = ecc_decrypt(encrypted, private_key)

print("ECC - Encrypted:", encrypted["ciphertext"])
print("")
print("ECC - Decrypted:", decrypted_message)
