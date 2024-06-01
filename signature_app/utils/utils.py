IV = b'\x91e\xc6\x11v\x04\x9bK\xa8\x85\x86\xa5Y\xe3*\xa4'

def read_key_from_file(key_file_path: str) -> bytes:
    try:
        with open(key_file_path, "rb") as f:
            key = f.read()
            print("Key read successfully.")
            return key

    except FileNotFoundError:
        raise Exception("No such file or directory")
    except Exception as err:
        raise Exception(f"Unexpected {err=}, {type(err)=}")

def read_doc(doc_file_path: str) -> bytes:
    try:
        with open(doc_file_path, "rb") as f:
            content = f.read()
            print("Document read successfully.")
            return content
    except FileNotFoundError:
        raise Exception("No such file or directory")
    except Exception as err:
        raise Exception(f"Unexpected {err=}, {type(err)=}")
