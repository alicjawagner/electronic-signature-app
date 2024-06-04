import tkinter as tk
from tkinter import filedialog, ttk
from signature_app.signing import Verifier


class Verification:
    def __init__(self, app_root):
        global verifier, root, error_label, result_label
        verifier = Verifier()
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

    def _obtain_public_key(self):
        root.withdraw()
        verifier.public_key_file_path = filedialog.askopenfilename()
        try:
            verifier.obtain_public_key()
            return self._verify_signature()
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def _verify_signature(self):
        root.withdraw()
        verifier.doc_file_path = filedialog.askopenfilename()
        verifier.signature_file_path = filedialog.askopenfilename()
        try:
            verifier.verify_signature()
            result = "Is signature valid: " + self._verify_signature()
            result_label.config(text=result)
            result_label.pack(pady=10)
            root.deiconify()
            return result
        except Exception as inst:
            err = str(inst.args[0]).removesuffix("'").removeprefix("'")
            error_label.config(text=err)
            error_label.pack(pady=10)
            root.deiconify()

    def verifi(self):
        return self._obtain_public_key()

