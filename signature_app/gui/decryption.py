import tkinter as tk
from tkinter import filedialog, ttk
from signature_app.encryption import Decryptor


class Decryption:
    def __init__(self, app_root):
        global decryptor, root, fields, submit_button, error_label
        decryptor = Decryptor()
        root = app_root

        # Entry pin
        fields = {}

        fields['pin_label'] = ttk.Label(text='Pin:')
        fields['pin'] = ttk.Entry(show="*")

        # Pin submit button
        submit_button = ttk.Button(
            root,
            text="Save",
            command=self._submit_pin
        )

        # Error label
        error_label = ttk.Label(
            root,
            text="Error",
            anchor="center",
            wraplength=500,
            padding=10,
            style='danger'
        )

    def _pin_fields_display(self):
        for field in fields.values():
            field.pack(anchor=tk.W, padx=10, pady=5, fill=tk.X)
        submit_button.pack(pady=10)

    def _pin_fields_hide(self):
        for field in fields.values():
            field.pack_forget()
        submit_button.pack_forget()

    def _submit_pin(self):
        if fields['pin'].get() != '':
            decryptor.pin_code = fields['pin'].get()
        self._obtain_private_key()

    def _check_pincode(self):
        self._pin_fields_display()

    def _obtain_private_key(self):
        root.withdraw()
        decryptor.private_key_file_path = filedialog.askopenfilename()
        try:
            decryptor.obtain_private_key()
            self._decrypt_and_save_file()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def _decrypt_and_save_file(self):
        self._pin_fields_hide()
        root.withdraw()
        decryptor.encrypted_doc_file_path = filedialog.askopenfilename()
        try:
            decryptor.decrypt_and_save_file()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def decrypt(self):
        self._check_pincode()

