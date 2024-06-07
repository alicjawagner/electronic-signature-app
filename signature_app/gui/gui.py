import tkinter as tk
from tkinter import ttk
from ttkbootstrap import Style

from signature_app.gui.utils import Functionality, execute_operate_on_file_function


def start_window():
    fields_hide()
    info_label.config(text=info_label_text)
    info_label.pack(pady=10)
    signature_button.pack(pady=10)
    verification_button.pack(pady=10)
    encryption_button.pack(pady=10)
    decryption_button.pack(pady=10)
    root.deiconify()


def fields_hide():
    ok_button.pack_forget()
    result_label.pack_forget()
    info_label.pack_forget()
    signature_button.pack_forget()
    verification_button.pack_forget()
    encryption_button.pack_forget()
    decryption_button.pack_forget()
    for field in fields.values():
        field.pack_forget()
    error_label.pack_forget()


def signature_run():
    fields_hide()
    execute_operate_on_file_function(Functionality.SIGN, root, fields_hide, start_window, info_label, ok_button,
                                     error_label, result_label, fields=fields)


def verification_run():
    fields_hide()
    execute_operate_on_file_function(Functionality.VERI, root, fields_hide, start_window, info_label, ok_button,
                                     error_label, result_label)


def encryption_run():
    fields_hide()
    execute_operate_on_file_function(Functionality.ENCR, root, fields_hide, start_window, info_label, ok_button,
                                     error_label, result_label)


def decryption_run():
    fields_hide()
    execute_operate_on_file_function(Functionality.DECR, root, fields_hide, start_window, info_label, ok_button,
                                     error_label, result_label, fields=fields)


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
info_label_text = "Choose functionality"
info_label = ttk.Label(
    root,
    text=info_label_text,
    anchor="center",
    wraplength=500,
    padding=10
)

# Buttons
signature_button = ttk.Button(
    root,
    text="Sign document",
    command=signature_run
)

verification_button = ttk.Button(
    root,
    text="Verify signature",
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

# Entry pin
fields = {}

fields['pin_label'] = ttk.Label(text='Pin:')
fields['pin'] = ttk.Entry(show="*")

# Result label
result_label = ttk.Label(
    root,
    text="Result",
    anchor="center",
    wraplength=500,
    padding=10,
    style='info'
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


# OK button
ok_button = ttk.Button(
    root,
    text="OK",
    command=start_window
)

start_window()

root.mainloop()
