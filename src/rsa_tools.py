from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
import base64

def generate_key_pair():
    """
    Generate a 2048-bit RSA key pair and return the keys as PEM-formatted strings.
    These are easy to display or save to files if needed.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Convert the private key to a PEM-encoded text form
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert the public key to a PEM-encoded text form
    pem_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private.decode('utf-8'), pem_public.decode('utf-8')

def sign_message(private_key_pem: str, message: str) -> str:
    """
    Sign the provided message with a private key using PSS+SHA256.
    The signature is returned as a Base64-encoded string.
    """
    # Load the private key object from its PEM text representation
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    
    # Produce the PSS+SHA256 signature over the message bytes
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem: str, message: str, signature_b64: str) -> bool:
    """
    Verify a signature using the public key.
    If the message was changed even by a single bit, returns False.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
        signature = base64.b64decode(signature_b64)
        
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True  # verification succeeded
    except InvalidSignature:
        return False  # signature invalid (or message altered)
    except Exception:
        return False