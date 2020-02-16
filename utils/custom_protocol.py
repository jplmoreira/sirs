# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/x25519/
# https://cryptography.io/en/latest/fernet/
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


class DHFernet:

    def __init__(self):
        self.private_key = X25519PrivateKey.generate()
        self.peer_public_key = None
        self.shared_secret = None

    def set_peer_public_key(self, peer_public_key: bytes):
        self.peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key)
        self.calculate_shared_secret()

    def get_public_key(self) -> bytes:
        return self.private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                          format=serialization.PublicFormat.Raw)

    def calculate_shared_secret(self):
        secret = self.private_key.exchange(self.peer_public_key)
        derived_key = HKDF(algorithm=hashes.SHA256(),
                           length=32,
                           salt=None,
                           info=b'diffie-hellman custom protocol',
                           backend=default_backend()
                           ).derive(secret)

        self.shared_secret = base64.urlsafe_b64encode(derived_key)

    def encrypt(self, paintext: bytes) -> bytes:
        f = Fernet(self.shared_secret)
        return f.encrypt(paintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        f = Fernet(self.shared_secret)
        return f.decrypt(ciphertext)
