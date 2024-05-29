from signature_app.signing import Signer

signer = Signer()
signer.pin_code = "542383"
signer.private_key_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\private_key.pem.enc"
signer.doc_file_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\studia\\semestr_6\\bsk\\projekt\\electronic-signature-app\\tests\\file1.cpp"
signer.obtain_private_key()
signer.create_xades_signature()

"""
import xades
import xmlsig

sign = xmlsig.template.create(c14n_method=xmlsig.constants.TransformExclC14N, sign_method=xmlsig.constants.TransformRsaSha256)
ref = xmlsig.template.add_reference(sign, xmlsig.constants.TransformSha1)
xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)
qualifying = template.create_qualifying_properties(signature)
props = template.create_signed_properties(qualifying)
policy = xades.policy.GenericPolicyId(
          policy_id,
          policy_name,
          xmlsig.constants.TransformSha1)
ctx = xades.XAdESContext(policy)
"""



"""
import hashlib
import xml.etree.ElementTree as ElemTree
import datetime

class SignatureProcessor:
    def __init__(self):
        pass

    def create_xades_signature(self, document, private_key, pin_number, user_info):
        # Generate hash of the document
        document_hash = hashlib.sha256(document.encode()).hexdigest()

        # Decrypt private key using AES algorithm and PIN number
        decrypted_private_key = obtain_private_key(private_key, pin_number)

        # Sign the document hash using the decrypted private key
        signature = sign_document_hash(document_hash, decrypted_private_key)

        # Create XML structure for the signature
        xml_signature = create_xml_signature(document, signature, user_info)

        return xml_signature

    def obtain_private_key(self, private_key, pin_number):
        # Implement decryption logic using AES algorithm and PIN number
        # Example: decrypted_private_key = aes_decrypt(private_key, pin_number)
        decrypted_private_key = private_key  # Placeholder, replace with actual decryption logic
        return decrypted_private_key

    def sign_document_hash(self, document_hash, private_key):
        # Implement signing logic using RSA algorithm and private key
        # Example: signature = rsa_sign(document_hash, private_key)
        signature = document_hash  # Placeholder, replace with actual signing logic
        return signature

    def create_xml_signature(self, document, signature, user_info):
        # Create XML structure for the signature
        root = ElemTree.Element("XAdES")

        document_info = ElemTree.SubElement(root, "DocumentInfo")
        ElemTree.SubElement(document_info, "Size").text = str(len(document))
        ElemTree.SubElement(document_info, "Extension").text = "pdf"  # Example extension
        ElemTree.SubElement(document_info, "DateOfModification").text = str(datetime.datetime.now())

        user_info_elem = ElemTree.SubElement(root, "UserInfo")
        ElemTree.SubElement(user_info_elem, "Name").text = user_info["name"]
        ElemTree.SubElement(user_info_elem, "Email").text = user_info["email"]

        ElemTree.SubElement(root, "EncryptedHash").text = signature
        ElemTree.SubElement(root, "Timestamp").text = str(datetime.datetime.now())

        xml_signature = ElemTree.tostring(root, encoding="unicode", method="xml")

        return xml_signature


# Example usage:
document = "Lorem ipsum dolor sit amet"
private_key = "PRIVATE_KEY_CONTENT"
pin_number = "1234"
user_info = {"name": "John Doe", "email": "john@example.com"}

xml_signature = create_xades_signature(document, private_key, pin_number, user_info)
print(xml_signature)
with open("C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo\\xml.xml", "w") as f:
    f.write(xml_signature)
    print("Saved successfully.")

"""
