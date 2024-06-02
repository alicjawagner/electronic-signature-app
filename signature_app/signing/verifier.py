import base64
import hashlib
import lxml.etree as ET
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signature_app.utils import IV, read_key_from_file, read_doc


class Verifier:
    def __init__(self, public_key_path: str = None, doc_path: str = None, signature_file_path: str = None):
        self.public_key_file_path: str = public_key_path
        self.doc_file_path: str = doc_path
        self.signature_file_path = signature_file_path
        self.public_key = None

    def obtain_public_key(self) -> None:
        """reads the key from file"""

        if self.public_key_file_path is None:
            raise Exception("No public key provided.")

        public_key = read_key_from_file(self.public_key_file_path)
        self.public_key = public_key

    def verify_signature(self) -> bool:
        """verifies if the signature is valid"""

        if self.doc_file_path is None:
            raise Exception("No document provided.")
        if self.signature_file_path is None:
            raise Exception("No signature file provided.")

        doc = read_doc(self.doc_file_path)
        doc_hash = hashlib.sha256(doc).digest()
        signature = self._get_signature_from_xml()
        if signature is None:
            return False
        are_the_same = self._verify_hashes(doc_hash, signature)
        return are_the_same

    def _get_signature_from_xml(self) -> bytes | None:
        try:
            tree = ET.parse(self.signature_file_path)
            root = tree.getroot()
            document_hash_element = root.find(".//DocumentHash")
            if document_hash_element is not None:
                document_hash = document_hash_element.text
                document_hash_bytes = base64.b64decode(document_hash)
                print("Encrypted hash read successfully.")
                return document_hash_bytes
        except (Exception,):
            return None

    def _verify_hashes(self, document: bytes, signature: bytes) -> bool:
        public_key = serialization.load_pem_public_key(
            self.public_key,
            backend=default_backend()
        )
        try:
            public_key.verify(
                signature,
                document,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified successfully.")
            return True
        except (Exception,):
            print(f"Signature verification unsuccessful.")
            return False
