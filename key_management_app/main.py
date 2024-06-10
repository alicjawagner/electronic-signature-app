"""
This file contains an example of using the application functionality.
To run an application with a graphical interface, run the gui.py file.
"""

from key_management import KeyManager

manager = KeyManager()
manager.dir_path = "path_to_directory"
manager.pin_code = "5423"
manager.encrypt_and_save_keys()
