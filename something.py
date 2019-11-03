from tkinter import *
from tkinter.font import Font
from tkinter import filedialog
import pyAesCrypt
import os
from re import match, compile
from random import choice
from platform import system

GENERATED_ALPHABET = list('abcdefghilklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890')
VALID_PASSWORD = compile(r'^[A-Za-zА-Яа-яЁё0-9]+$')
FILE_ENCRYPTED = compile(r'^.+\.locked$')


def clear_log():
    progress_field.config(state=NORMAL)
    progress_field.delete(1.0, END)
    progress_field.config(state=DISABLED)


def log_to_field(text):
    progress_field.insert(END, text + "\n")
    root.update()


def make_line():
    log_to_field("-" * 40)


def choose_directory():
    directory = filedialog.askdirectory()
    if directory is None or directory == "":
        return
    directoryEntry.delete(0, END)
    directoryEntry.insert(0, directory)


def crypt():
    crypt_option = option.get()
    if crypt_option == 1:
        encrypt_files()
    else:
        decrypt_files()


def generate_password():
    passwordEntry.delete(0, END)
    generated = ''
    for i in range(10):
        generated += choice(GENERATED_ALPHABET)
    passwordEntry.insert(0, generated)
    root.update()


def encrypt_files():
    progress_field.config(state=NORMAL)
    home_directory = directoryEntry.get()
    password = passwordEntry.get()
    if not os.path.isdir(home_directory):
        log_to_field("[error] Encryption failed because of the invalid path.")
        return
    if match(VALID_PASSWORD, password) is None:
        log_to_field("[error] Encryption failed because of the invalid password.")
        return
    log_to_field("Encrypting...")
    make_line()

    def encrypt(file):
        buffer_size = 512 * 1024
        pyAesCrypt.encryptFile(str(file), str(file) + ".locked", password, buffer_size)
        log_to_field("[encrypted]" + str(file) + ".locked")
        os.remove(file)

    def walk(directory):
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                if not match(FILE_ENCRYPTED, path):
                    encrypt(path)
                    make_line()
                else:
                    log_to_field("[error] The file %s was already encrypted." % path)
            else:
                walk(path)
    walk(home_directory)
    log_to_field("The files were encrypted.")
    progress_field.config(state=DISABLED)


def decrypt_files():
    progress_field.config(state=NORMAL)
    home_directory = directoryEntry.get()
    password = passwordEntry.get()
    crypt_option = option.get()
    if not os.path.isdir(home_directory):
        log_to_field("[error] Decryption failed because of the invalid path.")
        return
    if match(VALID_PASSWORD, password) is None:
        log_to_field("[error] Decryption failed because of the invalid password.")
        return
    log_to_field("Decrypting...")
    make_line()

    def decrypt(file):
        buffer_size = 512 * 1024
        pyAesCrypt.decryptFile(str(file), str(os.path.splitext(file)[0]), password, buffer_size)
        log_to_field("[decrypted] '" + str(os.path.splitext(file)[0]) + "'")
        os.remove(file)

    def walk(directory):
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                if match(FILE_ENCRYPTED, path):
                    decrypt(path)
                    make_line()
                else:
                    log_to_field("[error] The file %s was already decrypted." % path)
            else:
                walk(path)

    walk(home_directory)
    log_to_field("The files were decrypted.")
    progress_field.config(state=DISABLED)


root = Tk()
root.title("CRYPTO")
root.geometry("650x455")
root.resizable(0, 0)
if system() == "Windows":
    try:
        root.iconbitmap("locked-padlock.ico")
    except:
        pass
default_font = Font(root, family="Segoe UI Light", size=10)
main_frame = Frame(root)
text_frame = Frame(root)

option = IntVar(root)
option.set(1)

label0 = Label(main_frame, text="Welcome to Crypto!\nThis app allows you to encrypt/decrypt your files.",
               font=default_font)
label1 = Label(main_frame, text="Enter the directory will be encrypted/decrypted:", font=default_font)
label2 = Label(main_frame, text="Enter the password:", font=default_font)
label3 = Label(main_frame, text="Choose the option:", font=default_font)
directoryEntry = Entry(main_frame, font=default_font)
passwordEntry = Entry(main_frame, font=default_font)
chooseButton = Button(main_frame, text="Choose", font=default_font, relief=GROOVE, command=choose_directory)
generateButton = Button(main_frame, text="Generate", font=default_font, relief=GROOVE, command=generate_password)
cryptButton = Button(main_frame, text="CRYPT!", command=crypt, font=default_font, relief=GROOVE)
radioEncrypt = Radiobutton(main_frame, text="Encrypt", font=default_font, variable=option, value=1)
radioDecrypt = Radiobutton(main_frame, text="Decrypt", font=default_font, variable=option, value=2)

label_log = Label(text_frame, text="Log:", font=default_font)
clearButton = Button(text_frame, text="Clear log", command=clear_log, font=default_font, relief=GROOVE)
progress_field = Text(text_frame, width=40, height=21, font=default_font)
scroll_bar = Scrollbar(text_frame, command=progress_field.yview)
progress_field.config(yscrollcommand=scroll_bar.set)

# Packing all
main_frame.pack(side=LEFT)
text_frame.pack(side=RIGHT)

label0.grid(row=0, column=0, sticky=W, padx=10, pady=10, columnspan=2)
label1.grid(row=1, column=0, sticky=W, padx=10, pady=10, columnspan=2)
directoryEntry.grid(row=2, column=0, sticky=W, padx=10, pady=5)
chooseButton.grid(row=3, column=0, sticky=W, padx=10, pady=5)
label2.grid(row=4, column=0, sticky=W, padx=10, pady=10, columnspan=2)
passwordEntry.grid(row=5, column=0, sticky=W, padx=10, pady=5)
generateButton.grid(row=6, column=0, sticky=W, padx=10, pady=5)
label3.grid(row=7, column=0, sticky=W, padx=10, pady=10, columnspan=2)
radioEncrypt.grid(row=8, column=0, sticky=W, padx=10, pady=5)
radioDecrypt.grid(row=9, column=0, sticky=W, padx=10, pady=5)
cryptButton.grid(row=10, column=0, sticky=W, padx=10, pady=10)

clearButton.grid(row=2, column=0, sticky=W, pady=10)
progress_field.grid(row=1, column=0)
scroll_bar.grid(row=1, column=1, sticky=W+S+N)
label_log.grid(row=0, column=0, sticky=W, pady=10)

progress_field.config(state=DISABLED)
root.mainloop()