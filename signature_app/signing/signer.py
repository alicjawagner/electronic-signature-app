import base64
import hashlib
import os
import time
import lxml.etree as ET
from datetime import datetime
from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from signature_app.utils import IV, read_key_from_file, read_doc


class Signer:
    def __init__(self, private_key_path: str = None, pin_code: str = None, doc_path: str = None):
        self.private_key_file_path: str = private_key_path
        self.pin_code: str = pin_code
        self.doc_file_path: str = doc_path
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

    def create_xades_signature(self) -> None:
        """signs the document and creates xades"""

        if self.doc_file_path is None:
            raise Exception("No document provided.")

        doc = read_doc(self.doc_file_path)
        doc_hash = hashlib.sha256(doc).digest()
        signature = self._sign_document(doc_hash, self.private_key)
        self._create_and_write_xades(signature)

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
        print("Document signed successfully.")
        return signature

    def _create_and_write_xades(self, signature: bytes) -> None:
        root = ET.Element('XAdES')

        signature_info = ET.SubElement(root, 'SignatureInfo')

        signer_info = ET.SubElement(signature_info, 'SignerInfo')
        signer_info.text = 'User A'

        doc_info = ET.SubElement(signature_info, 'DocumentInfo')

        doc_size = ET.SubElement(doc_info, 'DocumentSize')
        doc_size.text = str(os.path.getsize(self.doc_file_path))

        doc_extension = ET.SubElement(doc_info, 'DocumentExtension')
        _, file_extension = os.path.splitext(self.doc_file_path)
        doc_extension.text = file_extension

        doc_modification = ET.SubElement(doc_info, 'DocumentModificationDate')
        doc_modification.text = time.ctime(os.path.getmtime(self.doc_file_path))

        doc_hash = ET.SubElement(doc_info, 'DocumentHash')
        doc_hash.text = base64.b64encode(signature)

        timestamp = ET.SubElement(signature_info, 'Timestamp')
        timestamp.text = datetime.now().isoformat()

        tree = ET.ElementTree(root)
        self._write_xml(tree)

    def _write_xml(self, xml_tree):
        dir_path, file_name = os.path.split(self.doc_file_path)
        file_name = os.path.splitext(file_name)[0]
        file_name = file_name + "_signature.xml"
        xml_path = os.path.join(dir_path, file_name)
        xml_tree.write(xml_path)
        print("Xml saved successfully.")
