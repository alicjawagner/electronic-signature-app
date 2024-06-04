import tkinter as tk
from tkinter import filedialog, ttk
from signature_app.signing import Signer


class Signature:
    def __init__(self, app_root):
        global signer, root, fields, submit_button, error_label
        signer = Signer()
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
            signer.pin_code = fields['pin'].get()
        self._obtain_private_key()

    def _check_pincode(self):
        self._pin_fields_display()

    def _obtain_private_key(self):
        root.withdraw()
        signer.private_key_file_path = filedialog.askopenfilename()
        try:
            signer.obtain_private_key()
            self._create_xades_signature()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def _create_xades_signature(self):
        self._pin_fields_hide()
        root.withdraw()
        signer.doc_file_path = filedialog.askopenfilename()
        try:
            signer.create_xades_signature()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def sign(self):
        self._check_pincode()

