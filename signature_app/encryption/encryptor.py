from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


class Encryptor:
    def __init__(self, public_key_path: str = None, doc_path: str = None):
        self.public_key_file_path: str = public_key_path
        self.doc_file_path: str = doc_path
        self.public_key = None

    def obtain_public_key(self) -> None:
        """reads the key from file"""

        if self.public_key_file_path is None:
            raise Exception("No public key provided.")

        public_key = self._read_key_from_file()
        self.public_key = public_key

    def encrypt_and_save_file(self) -> None:
        """encrypts and saves the encrypted file"""

        if self.doc_file_path is None:
            raise Exception("No document provided.")
        if self.public_key is None:
            raise Exception("No public key provided.")

        doc = self._read_doc()
        encrypted_file = self._encrypt_document(doc)
        self._write_encrypted_file(encrypted_file)

    def _read_key_from_file(self) -> bytes:
        try:
            with open(self.public_key_file_path, "rb") as f:
                public_key = f.read()
                print("Public key read successfully.")
                return public_key

        except FileNotFoundError:
            raise Exception("No such file or directory")
        except Exception as err:
            raise Exception(f"Unexpected {err=}, {type(err)=}")

    def _read_doc(self) -> bytes:
        try:
            with open(self.doc_file_path, "rb") as f:
                content = f.read()
                print("Document read successfully.")
                return content
        except FileNotFoundError:
            raise Exception("No such file or directory")
        except Exception as err:
            raise Exception(f"Unexpected {err=}, {type(err)=}")

    def _encrypt_document(self, document: bytes) -> bytes:
        public_key = serialization.load_pem_public_key(
            self.public_key,
            backend=default_backend()
        )
        try:
            encrypted_document = public_key.encrypt(
                document,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except (Exception,):
            raise Exception("Encryption unsuccessful. The file to be encrypted is probably too large.")

        print("Document encrypted successfully.")
        return encrypted_document

    def _write_encrypted_file(self, file: bytes) -> None:
        file_path = self.doc_file_path + ".enc"

        with open(file_path, "wb") as f:
            f.write(file)
            print("Encrypted file saved successfully.")
