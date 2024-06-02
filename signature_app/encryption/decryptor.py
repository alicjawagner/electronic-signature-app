import hashlib
import os
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signature_app.utils import read_key_from_file, read_doc, IV


class Decryptor:
    def __init__(self, private_key_path: str = None, pin_code: str = None, doc_path: str = None):
        self.private_key_file_path: str = private_key_path
        self.pin_code: str = pin_code
        self.encrypted_doc_file_path: str = doc_path
        self.private_key = None

    def obtain_private_key(self) -> None:
        """reads the key from file, decrypts it and checks if it has been successfully decrypted"""

        if self.pin_code is None:
            raise Exception("No pin code provided.")
        if self.private_key_file_path is None:
            raise Exception("No private key provided.")

        private_key_enc = read_key_from_file(self.private_key_file_path)
        self._decrypt_private_key(private_key_enc)
        correct = self._check_private_key()
        if not correct:
            raise Exception("Private key decryption unsuccessful.")

    def _decrypt_private_key(self, private_key_enc) -> None:
        key = hashlib.sha256(self.pin_code.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_CBC, IV)
        decrypted_data_padded = cipher.decrypt(private_key_enc)
        # decrypted_data = decrypted_data_padded.rstrip(b'\0').decode("UTF-8")
        decrypted_data = decrypted_data_padded.rstrip(b'\0')
        self.private_key = decrypted_data

    def _check_private_key(self) -> bool:
        try:
            if self.private_key.decode("UTF-8")[:26] == "-----BEGIN PRIVATE KEY----":
                return True
            else:
                return False
        except (Exception,):
            return False

    def decrypt_and_save_file(self) -> None:
        """decrypts and saves the decrypted file"""

        if self.encrypted_doc_file_path is None:
            raise Exception("No document provided.")
        if self.private_key is None:
            raise Exception("No private key provided.")

        doc = read_doc(self.encrypted_doc_file_path)
        decrypted_file = self._decrypt_document(doc)
        self._write_decrypted_file(decrypted_file)

    def _decrypt_document(self, document: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(
            self.private_key,
            password=None,
            backend=default_backend()
        )

        try:
            decrypted_document = private_key.decrypt(
                document,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except (Exception,):
            raise Exception("Decryption unsuccessful.")

        print("Document decrypted successfully.")
        return decrypted_document

    def _write_decrypted_file(self, file: bytes) -> None:
        dir_path, file_name = os.path.split(self.encrypted_doc_file_path)
        file_name = os.path.splitext(file_name)[0]
        file_name, ext = os.path.splitext(file_name)
        file_name = file_name + "_decrypted" + ext
        file_path = os.path.join(dir_path, file_name)

        with open(file_path, "wb") as f:
            f.write(file)
            print("Decrypted file saved successfully.")
