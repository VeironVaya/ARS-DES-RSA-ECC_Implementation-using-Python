import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom


def test_rsa():
    print("=== RSA Test ===")
    t0 = time.perf_counter()
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    t1 = time.perf_counter()
    pub = priv.public_key()
    print("Key generation (RSA 2048):", round(t1 - t0, 6), "s")

    plaintext = b"testing kriptografi"

    # Enkripsi
    t2 = time.perf_counter()
    ciphertext = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t3 = time.perf_counter()
    print("Encryption time:", round(t3 - t2, 6), "s")

    # Dekripsi
    t4 = time.perf_counter()
    decrypted = priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    t5 = time.perf_counter()
    print("Decryption time:", round(t5 - t4, 6), "s")
    assert decrypted == plaintext


def test_ecc():
    print("\n=== ECC Test ===")
    t0 = time.perf_counter()
    priv_a = ec.generate_private_key(ec.SECP256R1())
    priv_b = ec.generate_private_key(ec.SECP256R1())
    t1 = time.perf_counter()
    print("Key generation (ECC P-256):", round(t1 - t0, 6), "s")

    # Key exchange (ECDH)
    t2 = time.perf_counter()
    shared_a = priv_a.exchange(ec.ECDH(), priv_b.public_key())
    shared_b = priv_b.exchange(ec.ECDH(), priv_a.public_key())
    t3 = time.perf_counter()
    print("ECDH key exchange:", round(t3 - t2, 6), "s")
    assert shared_a == shared_b

    # Derive symmetric key (HKDF)
    t4 = time.perf_counter()
    derived_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b'handshake data'
    ).derive(shared_a)
    t5 = time.perf_counter()
    print("Key derivation (HKDF):", round(t5 - t4, 6), "s")

    # AES-GCM enkripsi & dekripsi
    aesgcm = AESGCM(derived_key)
    nonce = urandom(12)
    plaintext = b"pesan uji coba"

    # Enkripsi
    t6 = time.perf_counter()
    ct = aesgcm.encrypt(nonce, plaintext, None)
    t7 = time.perf_counter()
    print(f"Encryption time: {t7 - t6:.6f} s")


    # Dekripsi
    t8 = time.perf_counter()
    pt = aesgcm.decrypt(nonce, ct, None)
    t9 = time.perf_counter()
    print(f"Decryption time: {t9 - t8:.6f} s")
    assert pt == plaintext


if __name__ == "__main__":
    test_rsa()
    test_ecc()
