from signature_app.encryption import Encryptor
from signature_app.signing import Signer, Verifier

signer = Signer()
signer.pin_code = "542383"
signer.private_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\private_key.pem.enc"
signer.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\tests\\file1.cpp"
signer.obtain_private_key()
signer.create_xades_signature()

# encryptor works for small files only, our pdf is too big
enc = Encryptor()
enc.public_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\public_key.pem"
enc.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\tests\\file1.cpp"
enc.obtain_public_key()
enc.encrypt_and_save_file()

verifier = Verifier()
verifier.public_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\public_key.pem"
verifier.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\tests\\file1.cpp"
verifier.signature_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\tests\\file1_signature.xml"
verifier.obtain_public_key()
result = verifier.verify_signature()
print("Is signature valid:", result)
