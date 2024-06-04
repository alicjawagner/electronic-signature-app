import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style

from signature_app.gui.signature import Signature
from signature_app.gui.verification import Verification
from signature_app.gui.encryption import Encryption
from signature_app.gui.decryption import Decryption


def start_window():
    info_label.pack(pady=10)
    signature_button.pack(pady=10)
    verification_button.pack(pady=10)
    encryption_button.pack(pady=10)
    decryption_button.pack(pady=10)
    ok_button.pack_forget()
    result_label.pack_forget()
    ok_button.pack_forget()
    root.deiconify()


def fields_hide():
    ok_button.pack_forget()
    result_label.pack_forget()
    info_label.pack_forget()
    signature_button.pack_forget()
    verification_button.pack_forget()
    encryption_button.pack_forget()
    decryption_button.pack_forget()


def print_result(result):
    result_label.config(text=result)
    result_label.pack(pady=10)
    ok_button.pack(pady=10)
    root.deiconify()


def signature_run():
    fields_hide()
    window = Signature(root)
    window.sign()


def verification_run():
    fields_hide()
    window = Verification(root)
    print_result(window.verifi())


def encryption_run():
    fields_hide()
    window = Encryption(root)
    print_result(window.encrypt())


def decryption_run():
    fields_hide()
    window = Decryption(root)
    window.decrypt()


# Window
root = tk.Tk()
root.title("Signature app")
root.geometry("620x550")

# Style
style = Style(theme="sandstone")
style.configure("TLabel", font=("Helvetica", 17))
style.configure("TButton", font=("Helvetica", 16))
small_info_font = font = ("Helvetica", 12)

# Info label
info_label = ttk.Label(
    root,
    text="Choose functionality",
    anchor="center",
    wraplength=500,
    padding=10
)

# Button
signature_button = ttk.Button(
    root,
    text="Make signature",
    command=signature_run
)

verification_button = ttk.Button(
    root,
    text="Verificate signature",
    command=verification_run
)

encryption_button = ttk.Button(
    root,
    text="Encrypt file",
    command=encryption_run
)

decryption_button = ttk.Button(
    root,
    text="Decrypt file",
    command=decryption_run
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

# OK button
ok_button = ttk.Button(
    root,
    text="OK",
    command=start_window
)

start_window()

root.mainloop()
