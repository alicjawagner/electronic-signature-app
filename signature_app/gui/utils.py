import tkinter as tk
from tkinter import filedialog, ttk
from enum import Enum

from signature_app.encryption import Encryptor, Decryptor
from signature_app.signing import Verifier, Signer


class Functionality(Enum):
    SIGN = 1
    VERI = 2
    ENCR = 3
    DECR = 4


def hide_all_fields():
    hide_all_ptr()
    hide_extra_fields()
    set_visibility_menu_button(False)


def set_visibility_menu_button(show=True):
    if show:
        menu_button.pack(pady=50)
    else:
        menu_button.pack_forget()


def return_to_menu():
    hide_all_fields()
    main_window_func_ptr()


def print_what_asks(text, button_func, hide=True, create_new=False):
    if hide:
        hide_all_fields()

    if not create_new:
        info_label_ptr.config(text=text)
        info_label_ptr.pack(pady=10)

        ok_button_ptr.configure(command=button_func)
        ok_button_ptr.pack(pady=10)
    else:
        label = ttk.Label(
            root_ptr,
            text=text,
            anchor="center",
            wraplength=500,
            padding=10
        )
        extra_fields.append(label)
        extra_fields[-1].pack(pady=10)
        button = ttk.Button(
            root_ptr,
            text="OK",
            command=button_func
        )
        extra_fields.append(button)
        extra_fields[-1].pack(pady=10)


def show_in_label(text):
    label = ttk.Label(
        root_ptr,
        text=text,
        anchor="center",
        wraplength=500,
        padding=4,
        font=("Helvetica", 10)
    )
    extra_fields.append(label)
    extra_fields[-1].pack(pady=4)


def hide_extra_fields():
    for field in extra_fields:
        field.pack_forget()


def get_doc_file_path():
    function = None
    match functionality:
        case Functionality.SIGN:
            function = create_xades_signature
        case Functionality.VERI:
            function = get_signature_file_path
        case Functionality.ENCR:
            function = encrypt_and_save_file
        case Functionality.DECR:
            function = decrypt_and_save_file
        case _:
            hide_all_fields()
            error_label_ptr.config(text="Error in application executing. Incorrect functionality type.")
            error_label_ptr.pack(pady=10)
    print_what_asks("Please choose document file.",
                    function)
    set_visibility_menu_button()


def verification_save_doc_file():
    path = get_file_path()
    executing_class.doc_file_path = path
    show_in_label("Chosen file: " + path)
    set_visibility_menu_button()


def verification_save_signature_file():
    path = get_file_path()
    executing_class.signature_file_path = path
    show_in_label("Chosen file: " + path)
    set_visibility_menu_button()


def get_doc_files_paths():
    print_what_asks("Please choose document file.",
                    verification_save_doc_file)
    print_what_asks("Please choose signature file.", verification_save_signature_file, hide=False, create_new=True)

    submit = ttk.Button(
        root_ptr,
        text="Submit",
        command=verify_signature
    )
    extra_fields.append(submit)
    extra_fields[-1].pack(pady=10)
    set_visibility_menu_button()


def get_file_path():
    path = filedialog.askopenfilename()
    return None if path == '' else path


def get_public_key():
    print_what_asks("Please choose public key file.", obtain_key)
    set_visibility_menu_button()


def get_signature_file_path():
    executing_class.doc_file_path = get_file_path()
    print_what_asks("Please choose signature file.", verify_signature)
    set_visibility_menu_button()


def obtain_key():
    if functionality is Functionality.SIGN or functionality is Functionality.DECR:
        if fields_ptr['pin'].get() != '':
            executing_class.pin_code = fields_ptr['pin'].get()
        executing_class.private_key_file_path = get_file_path()
        try_function_execute(executing_class.obtain_private_key, get_doc_file_path)
    elif functionality is Functionality.VERI or functionality is Functionality.ENCR:
        executing_class.public_key_file_path = get_file_path()
        if functionality is Functionality.ENCR:
            try_function_execute(executing_class.obtain_public_key, get_doc_file_path)
        elif functionality is Functionality.VERI:
            try_function_execute(executing_class.obtain_public_key, get_doc_files_paths)


def get_pincode():
    for field in fields_ptr.values():
        field.pack(anchor=tk.W, padx=10, pady=5, fill=tk.X)

    print_what_asks("Please choose private key file.", obtain_key, hide=False)
    set_visibility_menu_button()


def create_xades_signature():
    executing_class.doc_file_path = get_file_path()
    try_function_execute(executing_class.create_xades_signature, main_window_func_ptr, bool_true="The signature is valid", bool_false="The signature is invalid")


def decrypt_and_save_file():
    executing_class.encrypted_doc_file_path = get_file_path()
    try_function_execute(executing_class.decrypt_and_save_file, main_window_func_ptr, text="Decryption successful")


def verify_signature():
    try_function_execute(executing_class.verify_signature, main_window_func_ptr, text="Is signature valid: ",
                         print_result=True)


def encrypt_and_save_file():
    executing_class.doc_file_path = get_file_path()
    try_function_execute(executing_class.encrypt_and_save_file, main_window_func_ptr, text="Encryption successful")


def print_error(err):
    error_label_ptr.config(text=err)
    error_label_ptr.pack(pady=10)
    root_ptr.deiconify()


def try_function_execute(function_ptr, next_function, text=None, bool_true=None, bool_false=None):
    try:
        if (bool_true is not None) and (bool_false is not None):
            result = function_ptr()
            print_what_asks(bool_true if result else bool_false, next_function)
        else:
            function_ptr()
            if text is None:
                next_function()
            else:
                print_what_asks(text, next_function)
    except Exception as inst:
        err = str(inst.args[0]).removesuffix("'").removeprefix("'")
        print_error(err)


def mach_functionality_operation():
    global executing_class
    match functionality:
        case Functionality.SIGN:
            if fields_ptr is None:
                print_error("Error in application executing. No attributes.")
            else:
                executing_class = Signer()
                get_pincode()
        case Functionality.VERI:
            executing_class = Verifier()
            get_public_key()
        case Functionality.ENCR:
            executing_class = Encryptor()
            get_public_key()
        case Functionality.DECR:
            if fields_ptr is None:
                print_error("Error in application executing. No attributes.")
            else:
                executing_class = Decryptor()
                get_pincode()
        case _:
            hide_all_fields()
            error_label_ptr.config(text="Error in application executing. Incorrect functionality type.")
            error_label_ptr.pack(pady=10)


def execute_operate_on_file_function(functionality_exec, root, hide_all, main_window_func, info_label, ok_button,
                                     error_label, result_label, fields=None):
    global root_ptr, functionality, hide_all_ptr, main_window_func_ptr, error_label_ptr, result_label_ptr, ok_button_ptr, info_label_ptr, fields_ptr, extra_fields
    functionality = functionality_exec
    root_ptr = root
    hide_all_ptr = hide_all
    main_window_func_ptr = main_window_func
    error_label_ptr = error_label
    result_label_ptr = result_label
    ok_button_ptr = ok_button
    info_label_ptr = info_label
    fields_ptr = fields

    global menu_button
    menu_button = ttk.Button(
        root_ptr,
        text="Go back to menu",
        command=return_to_menu,
        style='secondary.Outline.TButton'
    )

    extra_fields = []

    mach_functionality_operation()
