from key_management import KeyManager

manager = KeyManager()
manager.dir_path = "C:\\Users\\alicj\\OneDrive\\Pulpit\\myrepo"
manager.pin_code = "5423"
manager.encrypt_and_save_keys()
