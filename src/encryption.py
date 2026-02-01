import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, salt_hex: str) -> bytes:
    """
    Turn a user password into a 32-byte AES key using PBKDF2 (SHA-256).
    PBKDF2 with many iterations helps slow down brute-force attacks.
    """
    salt = bytes.fromhex(salt_hex)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_secret(password: str, salt_hex: str, plain_text: str) -> str:
    """
    Encrypt text using AES-GCM.
    Returns a string containing nonce + ciphertext (base64-encoded).
    """
    key = derive_key(password, salt_hex)
    aesgcm = AESGCM(key)
    
    # Generate a 12-byte nonce (IV) for AES-GCM. It must be unique per encryption.
    nonce = os.urandom(12)
    data = plain_text.encode()
    
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=None)
    
    # Prepend the nonce to the ciphertext and return everything base64-encoded
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_secret(password: str, salt_hex: str, encrypted_blob: str) -> str:
    """
    Decrypt the blob produced by `encrypt_secret`. If decryption fails
    (wrong password or corrupted data) an error message is returned.
    """
    try:
        key = derive_key(password, salt_hex)
        aesgcm = AESGCM(key)
        
        data = base64.b64decode(encrypted_blob)
        nonce = data[:12]      # Extract the 12-byte nonce from the start
        ciphertext = data[12:] # The remainder is the ciphertext
        
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
        return plaintext.decode('utf-8')
    except Exception as e:
        return "[ОШИБКА] Не удалось расшифровать. Возможно, неверный пароль или данные повреждены."