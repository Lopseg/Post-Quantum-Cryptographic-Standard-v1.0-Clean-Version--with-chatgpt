"""
Post-Quantum Cryptographic Standard v1.0

A post-quantum cryptographic suite combining:
- Kyber1024 for key encapsulation (KEM)
- AES-256-GCM for symmetric authenticated encryption
- Dilithium5 for digital signatures
"""

from pqcrypto.kem.kyber1024 import (
    generate_keypair as kyber_keygen,
    encapsulate,
    decapsulate
)

from pqcrypto.sign.dilithium5 import (
    generate_keypair as dil_keygen,
    sign,
    verify
)

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ------------------------------------------------------------
# 1. Key Generation (KEM + Digital Signature Keys)
# ------------------------------------------------------------
def generate_keys():
    """
    Generates all keys required by the PQC Standard:
    - Kyber1024 KEM keypair (public/private)
    - Dilithium5 signature keypair (public/private)
    """
    kyber_pub, kyber_priv = kyber_keygen()
    dil_pub, dil_priv = dil_keygen()

    return {
        "kyber_public": kyber_pub,
        "kyber_private": kyber_priv,
        "dilithium_public": dil_pub,
        "dilithium_private": dil_priv
    }


# ------------------------------------------------------------
# 2. Encryption (Kyber + AES-256-GCM)
# ------------------------------------------------------------
def encrypt_message(message: bytes, kyber_public: bytes):
    """
    Encrypts a message:

    1. A shared secret is generated via Kyber1024 encapsulation.
    2. AES-256-GCM is used for authenticated encryption.
    """
    kem_ct, shared_key = encapsulate(kyber_public)
    aes_key = shared_key[:32]  # 256 bits

    iv = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(message)

    return {
        "kem_ciphertext": kem_ct,
        "aes_iv": iv,
        "aes_tag": tag,
        "aes_ciphertext": ciphertext
    }


# ------------------------------------------------------------
# 3. Decryption (Kyber + AES-256-GCM)
# ------------------------------------------------------------
def decrypt_message(bundle: dict, kyber_private: bytes):
    """
    Decrypts data encrypted using encrypt_message().
    """
    shared_key = decapsulate(bundle["kem_ciphertext"], kyber_private)
    aes_key = shared_key[:32]

    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=bundle["aes_iv"])
    plaintext = cipher.decrypt_and_verify(
        bundle["aes_ciphertext"],
        bundle["aes_tag"]
    )
    return plaintext


# ------------------------------------------------------------
# 4. Digital Signatures (Dilithium5)
# ------------------------------------------------------------
def sign_message(message: bytes, dilithium_private: bytes):
    """Signs a message using Dilithium5."""
    return sign(message, dilithium_private)


def verify_signature(message: bytes, signature: bytes, dilithium_public: bytes) -> bool:
    """Verifies a Dilithium5 signature."""
    try:
        verify(message, signature, dilithium_public)
        return True
    except Exception:
        return False


# ------------------------------------------------------------
# 5. High-Level API (Optional)
# ------------------------------------------------------------
def secure_send(message: bytes, sender_priv: dict, recipient_pub: dict):
    """
    High-level secure send:
    - Encrypts the message
    - Signs the encrypted payload
    """
    encrypted = encrypt_message(message, recipient_pub["kyber_public"])
    signature = sign_message(
        encrypted["aes_ciphertext"],
        sender_priv["dilithium_private"]
    )

    encrypted["signature"] = signature
    return encrypted


def secure_receive(bundle: dict, recipient_priv: dict, sender_pub: dict):
    """
    High-level secure receive:
    - Verifies signature
    - Decrypts message
    """
    if not verify_signature(
        bundle["aes_ciphertext"],
        bundle["signature"],
        sender_pub["dilithium_public"]
    ):
        raise ValueError("Invalid signature.")

    return decrypt_message(bundle, recipient_priv["kyber_private"])
