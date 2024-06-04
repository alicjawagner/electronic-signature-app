import tkinter as tk
from tkinter import filedialog, ttk
from signature_app.encryption import Encryptor


class Encryption:
    def __init__(self, app_root):
        global encryptor, root, error_label, result_label, info_label, choose_button
        encryptor = Encryptor()
        root = app_root

        # Error label
        error_label = ttk.Label(
            root,
            text="Error",
            anchor="center",
            wraplength=500,
            padding=10,
            style='danger'
        )

        # Result label
        result_label = ttk.Label(
            root,
            text="Error",
            anchor="center",
            wraplength=500,
            padding=10,
            style='info'
        )

        # Info label
        info_label = ttk.Label(
            root,
            text="Info",
            anchor="center",
            wraplength=500,
            padding=10,
            style='info'
        )

        # Choose button
        choose_button = ttk.Button(
            root,
            text="Choose",
            command=self._obtain_public_key
        )

    def _print_what_asks(self, text, button_func):
        error_label.pack_forget()
        result_label.pack_forget()

        # info_label.config(text=text)
        # info_label.pack(pady=10)
        #
        # choose_button.configure(command=button_func)
        # choose_button.pack(pady=10)

    def _get_public_key(self):
        self._print_what_asks("Please choose public key file.", self._obtain_public_key)

    def _obtain_public_key(self):
        encryptor.public_key_file_path = filedialog.askopenfilename()
        try:
            encryptor.obtain_public_key()
            return self._encrypt_and_save_file()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def _get_doc_file_path(self):
        self._print_what_asks("Please choose document file", self._encrypt_and_save_file())

    def _encrypt_and_save_file(self):
        encryptor.doc_file_path = filedialog.askopenfilename()
        try:
            encryptor.encrypt_and_save_file()
            return "Encryption successfully"
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def encrypt(self):
        return self._get_public_key()

