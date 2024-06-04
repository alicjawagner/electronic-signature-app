import tkinter as tk
from tkinter import filedialog
from enum import Enum

from signature_app.encryption import Encryptor, Decryptor
from signature_app.signing import Verifier, Signer


class Functionality(Enum):
    SIGN = 1
    VERI = 2
    ENCR = 3
    DECR = 4


def print_what_asks(text, button_func):
    hide_all_ptr()

    info_label_ptr.config(text=text)
    info_label_ptr.pack(pady=10)

    ok_button_ptr.configure(command=button_func)
    ok_button_ptr.pack(pady=10)


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
            hide_all_ptr()
            error_label_ptr.config(text="Error in application executing. Incorrect functionality type.")
            error_label_ptr.pack(pady=10)
    print_what_asks("Please choose document file.",
                    function)


def get_public_key():
    print_what_asks("Please choose public key file.", obtain_key)


def get_signature_file_path():
    executing_class.doc_file_path = filedialog.askopenfilename()
    print_what_asks("Please choose signature file.", verify_signature)


def submit_pin():
    if fields_ptr['pin'].get() != '':
        executing_class.pin_code = fields_ptr['pin'].get()
    print_what_asks("Please choose private key file.", obtain_key)


def obtain_key():
    if functionality is Functionality.SIGN or functionality is Functionality.DECR:
        executing_class.private_key_file_path = filedialog.askopenfilename()
        try_function_execute(executing_class.obtain_private_key, get_doc_file_path)
    elif functionality is Functionality.VERI or functionality is Functionality.ENCR:
        executing_class.public_key_file_path = filedialog.askopenfilename()
        try_function_execute(executing_class.obtain_public_key, get_doc_file_path)


def get_pincode():
    for field in fields_ptr.values():
        field.pack(anchor=tk.W, padx=10, pady=5, fill=tk.X)
    submit_button_ptr.configure(command=submit_pin)
    submit_button_ptr.pack(pady=10)


def create_xades_signature():
    executing_class.doc_file_path = filedialog.askopenfilename()
    try_function_execute(executing_class.create_xades_signature, main_window_func_ptr, text="Signature successfully")


def decrypt_and_save_file():
    executing_class.encrypted_doc_file_path = filedialog.askopenfilename()
    try_function_execute(executing_class.decrypt_and_save_file, main_window_func_ptr, text="Decryption successfully")


def verify_signature():
    executing_class.signature_file_path = filedialog.askopenfilename()
    try_function_execute(executing_class.verify_signature, main_window_func_ptr, text="Is signature valid: ",
                         print_result=True)


def encrypt_and_save_file():
    executing_class.doc_file_path = filedialog.askopenfilename()
    try_function_execute(executing_class.encrypt_and_save_file, main_window_func_ptr, text="Encryption successfully")


def print_error(err):
    error_label_ptr.config(text=err)
    error_label_ptr.pack(pady=10)
    root_ptr.deiconify()


def try_function_execute(function_ptr, next_function, text=None, print_result=False):
    try:
        if print_result:
            result = function_ptr()
            print_what_asks(text + result, next_function)
        else:
            next_function()
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
            if submit_button_ptr is None or fields_ptr is None:
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
            if submit_button_ptr is None or fields_ptr is None:
                print_error("Error in application executing. No attributes.")
            else:
                executing_class = Decryptor()
                get_pincode()
        case _:
            hide_all_ptr()
            error_label_ptr.config(text="Error in application executing. Incorrect functionality type.")
            error_label_ptr.pack(pady=10)


def execute_operate_on_file_function(functionality_exec, root, hide_all, main_window_func, info_label, choose_button,
                                     error_label, result_label, fields=None, submit_button=None):
    global root_ptr, functionality, hide_all_ptr, main_window_func_ptr, error_label_ptr, result_label_ptr, ok_button_ptr, info_label_ptr, fields_ptr, submit_button_ptr
    functionality = functionality_exec
    root_ptr = root
    hide_all_ptr = hide_all
    main_window_func_ptr = main_window_func
    error_label_ptr = error_label
    result_label_ptr = result_label
    ok_button_ptr = choose_button
    info_label_ptr = info_label
    fields_ptr = fields
    submit_button_ptr = submit_button

    mach_functionality_operation()
