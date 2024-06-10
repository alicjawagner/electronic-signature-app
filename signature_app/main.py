"""
This file contains an example of using the application functionality.
To run an application with a graphical interface, run the gui.py file.
"""

from signature_app.encryption import Encryptor, Decryptor
from signature_app.signing import Signer, Verifier

# signature
signer = Signer()
signer.pin_code = "5423"
signer.private_key_file_path = "path_to_private_key"
signer.obtain_private_key()
signer.doc_file_path = "path_to_document"
signer.create_xades_signature()

# signature verification
verifier = Verifier()
verifier.public_key_file_path = "path_to_public_key"
verifier.obtain_public_key()
verifier.doc_file_path = "path_to_document"
verifier.signature_file_path = "path_to_xml_signature"
result = verifier.verify_signature()
print("Is signature valid:", result)

# file encryption
# encryptor works for small files only
encryptor = Encryptor()
encryptor.public_key_file_path = "path_to_public_key"
encryptor.obtain_public_key()
encryptor.doc_file_path = "path_to_document"
encryptor.encrypt_and_save_file()

# file decryption
decryptor = Decryptor()
decryptor.pin_code = "5423"
decryptor.private_key_file_path = "path_to_private_key"
decryptor.obtain_private_key()
decryptor.encrypted_doc_file_path = "path_to_encrypted_document"
decryptor.decrypt_and_save_file()
