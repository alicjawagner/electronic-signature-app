import tkinter as tk
from tkinter import messagebox, ttk, Entry, LEFT
from tkmacosx import Button
from tkinter import filedialog
from ttkbootstrap import Style

from key_management_app.key_management import KeyManager


def choose_folder():
    global folder_selected
    root.withdraw()
    folder_selected = filedialog.askdirectory()
    set_pin_code()


def submit_pin():
    global fields, error_label, folder_selected
    pin = fields['pin'].get()
    repeated = fields['repeated'].get()

    if pin != repeated:
        error_label.config(text="Repeated pin incorrect.")
        error_label.pack(pady=10)
        return

    try:
        integer = int(pin)
    except:
        error_label.config(text="Pin must be integer.")
        error_label.pack(pady=10)

    if len(pin) != 4:
        error_label.config(text="Incorrect pin length. Pin length should be 4.")
        error_label.pack(pady=10)

    else:
        key_manager = KeyManager(folder_selected, pin)
        key_manager.encrypt_and_save_keys()
        success()


def start_window():
    global info_label, choose_button
    info_label.pack(pady=10)
    choose_button.pack(pady=10)
    entry_fields_hide()
    submit_button.pack_forget()
    error_label.pack_forget()
    root.deiconify()


def success():
    start_window()
    messagebox.showinfo("Keys generated", "Keys generated successfully!")


def set_pin_code():
    global info_label, choose_button, submit_button
    info_label.config(text="Enter pin code")
    choose_button.pack_forget()
    entry_fields_display()
    submit_button.pack(pady=10)
    root.deiconify()


def entry_fields_display():
    global fields
    for field in fields.values():
        field.pack(anchor=tk.W, padx=10, pady=5, fill=tk.X)


def entry_fields_hide():
    global fields
    for field in fields.values():
        field.pack_forget()


# Variables
folder_selected = ""

# Window
root = tk.Tk()
root.title("Key management app")
root.geometry("620x550")

# Style
style = Style(theme="sandstone")
style.configure("TLabel", font=("Helvetica", 17))
style.configure("TButton", font=("Helvetica", 16))
small_info_font = font=("Helvetica", 12)

# Info label
info_label = ttk.Label(
    root,
    text="Choose folder",
    anchor="center",
    wraplength=500,
    padding=10
)

# Choose button
choose_button = ttk.Button(
    root,
    text="Choose",
    command=choose_folder
)

# Entry pin
fields = {}

fields['pin_label'] = ttk.Label(text='Pin:')
fields['pin'] = ttk.Entry(show="*")

fields['repeated_label'] = ttk.Label(text='Repeated pin:')
fields['repeated'] = ttk.Entry(show="*")

# Pin submit button
submit_button = ttk.Button(
    root,
    text="Save",
    command=submit_pin
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

start_window()

root.mainloop()
