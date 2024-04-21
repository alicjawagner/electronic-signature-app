import base64
import hashlib
import sys

from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signature_app.signing import SignatureProcessor


class Signer(SignatureProcessor):
    def __init__(self, private_key_path: str = None, pin_code: str = None, doc_path: str = None):
        super().__init__()
        self.private_key_file_path: str = private_key_path
        self.pin_code: str = pin_code
        self.doc_file_path: str = doc_path
        self.private_key = None

    def obtain_private_key(self) -> None:
        """reads the key from file, decrypts it and checks if it has been successfully decrypted"""

        if self.pin_code is None:
            print("No pin code provided. Provide a pin to complete the procedure.", file=sys.stderr)
            return
        if self.private_key_file_path is None:
            print("""No private key provided. Provide the path to the file
                     with your private key to complete the procedure.""", file=sys.stderr)
            return

        private_key_enc = self._read_key_from_file()
        self._decrypt_private_key(private_key_enc)
        correct = self._check_private_key()
        # TODO co jak jest niepoprawny

    def create_xades_signature(self) -> None:
        """signs the document and creates xades"""

        if self.doc_file_path is None:
            print("""No document provided. Provide the path to the document
            you want to sign to complete the procedure.""", file=sys.stderr)
            return

        doc = self._read_doc()
        doc_hash = hashlib.sha256(doc.encode('utf-8')).digest()
        signature = self._sign_document(doc_hash, self.private_key)
        # xml_signature = create_xml_signature(document, signature, user_info)
        self._create_and_write_xades(signature)

    def _read_key_from_file(self) -> bytes:
        try:
            with open(self.private_key_file_path, "rb") as f:
                private_key_enc = f.read()
                print("Private key read successfully.")
                return private_key_enc

        except FileNotFoundError:
            print("No such file or directory", file=sys.stderr)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}", file=sys.stderr)

    def _decrypt_private_key(self, private_key_enc) -> None:
        key = hashlib.sha256(self.pin_code.encode('utf-8')).digest()
        cipher = AES.new(key, AES.MODE_CBC, self.IV)
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
            print("Wrong pin. Private key not decrypted.", file=sys.stderr)
            return False

    def _read_doc(self) -> str:
        # TODO nie dziala dla pdf, cpp chyba dziala
        try:
            with open(self.doc_file_path, "r") as f:
                content = f.read()
                print("Document read successfully.")
                return content
        except FileNotFoundError:
            print("No such file or directory", file=sys.stderr)
        except Exception as err:
            print(f"Unexpected {err=}, {type(err)=}", file=sys.stderr)

    @staticmethod
    def _sign_document(document: bytes, private_key: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(
            private_key,
            password=None,
            backend=default_backend()
        )
        signature = private_key.sign(
            document,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def _create_and_write_xades(self, signature: bytes) -> None:
        # TODO
        print(base64.b64encode(signature))
        pass
