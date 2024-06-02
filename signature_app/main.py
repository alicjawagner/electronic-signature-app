from signature_app.encryption import Encryptor, Decryptor
from signature_app.signing import Signer, Verifier

# signature
signer = Signer()
signer.pin_code = "5423"
signer.private_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\private_key.pem.enc"
signer.obtain_private_key()
signer.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\test_files\\sample.pdf"
signer.create_xades_signature()

# signature verification
verifier = Verifier()
verifier.public_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\public_key.pem"
verifier.obtain_public_key()
verifier.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\test_files\\sample.pdf"
verifier.signature_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\test_files\\sample_signature.xml"
result = verifier.verify_signature()
print("Is signature valid:", result)

# file encryption
# encryptor works for small files only, our pdf is too big
encryptor = Encryptor()
encryptor.public_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\public_key.pem"
encryptor.obtain_public_key()
encryptor.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\test_files\\file1.cpp"
encryptor.encrypt_and_save_file()

# file decryption
decryptor = Decryptor()
decryptor.pin_code = "5423"
decryptor.private_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\private_key.pem.enc"
decryptor.obtain_private_key()
decryptor.encrypted_doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\test_files\\file1.cpp.enc"
decryptor.decrypt_and_save_file()
