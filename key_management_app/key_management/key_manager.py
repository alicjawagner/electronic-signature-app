import hashlib
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES

class KeyManager:
    """class for creating and encrypting RSA keys"""

    KEY_SIZE = 4096
    PRIVATE_KEY_FILE_NAME = "private_key.pem.enc"
    PUBLIC_KEY_FILE_NAME = "public_key.pem"
    IV = b'\x91e\xc6\x11v\x04\x9bK\xa8\x85\x86\xa5Y\xe3*\xa4'

    def __init__(self, dir_path: str = None, pin_code: str = None):
        self.dir_path: str = dir_path
        self.pin_code: str = pin_code
        (self.private_key, self.public_key) = self.generate_rsa_keypair()
        self.private_key_enc = None

    def generate_rsa_keypair(self) -> tuple[bytes, bytes]:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.KEY_SIZE,
            backend=default_backend()
        )

        public_key = private_key.public_key()

        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print("Generated a pair of keys.")
        return pem_private_key, pem_public_key

    def encrypt_private_key(self) -> None:
        if self.pin_code is None:
            print("No pin code provided. Encryption unsuccessful.")
            return None

        key = hashlib.sha256(self.pin_code.encode('utf-8')).digest()
        data = self.private_key
        padded_data = data + b"\0" * (AES.block_size - len(data) % AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, self.IV)
        encrypted_data = cipher.encrypt(padded_data)
        self.private_key_enc = encrypted_data
        # encrypted_base64 = base64.b64encode(encrypted_data)
        print("Successfully encrypted the private key.")

        # HOW TO DECRYPT:
        # key = hashlib.sha256(pin_code.encode('utf-8')).digest()
        # cipher = AES.new(key, AES.MODE_CBC, iv)
        # decrypted_data_padded = cipher.decrypt(encrypted_data) # encrypted data = encrypted key
        # decrypted_data = decrypted_data_padded.rstrip(b'\0').decode("UTF-8")

    def save_rsa_keypair(self) -> None:
        try:
            private_key_file = os.path.join(self.dir_path, self.PRIVATE_KEY_FILE_NAME)
            public_key_file = os.path.join(self.dir_path, self.PUBLIC_KEY_FILE_NAME)

            with open(private_key_file, "wb") as f:
                f.write(self.private_key_enc)
                print("Private key saved successfully.")

            with open(public_key_file, "wb") as f:
                f.write(self.public_key)
                print("Public key saved successfully.")

        except TypeError as err:
            print("Incorrect path:", err)
        except FileNotFoundError:
            print("No such file or directory")
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}")
