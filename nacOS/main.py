import time
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from alive_progress import alive_bar

BuildVersion = "0.1.0"

# Only these exact filenames will be skipped (case-sensitive)
EXCLUDED_FILES = ["users.nacprf", "NonEcnryptCache.nacprf", "settings.nacprf", "main.py"]


# === KEY DERIVATION FUNCTION ===
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())


# === ENCRYPT A SINGLE FILE IN PLACE ===
def encrypt_in_place(file_path, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    with open(file_path, "rb") as f:
        data = f.read()

    encrypted = aesgcm.encrypt(nonce, data, None)

    with open(file_path, "wb") as f:
        f.write(salt + nonce + encrypted)

    print(f"[+] Encrypted: {file_path}")


# === DECRYPT A SINGLE FILE IN PLACE ===
def decrypt_in_place(file_path, password):
    with open(file_path, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    decrypted = aesgcm.decrypt(nonce, ciphertext, None)

    with open(file_path, "wb") as f:
        f.write(decrypted)

    print(f"[+] Decrypted: {file_path}")


# === CHECK IF FILE IS IN EXCLUSION LIST ===
def is_excluded(file_path):
    filename = os.path.basename(file_path)
    return filename in EXCLUDED_FILES


# === RECURSIVE FOLDER ENCRYPTION ===
def encrypt_folder(folder_path, password):
    for root, _, files in os.walk(folder_path):
        for name in files:
            full_path = os.path.join(root, name)
            if is_excluded(full_path):
                print(f"[!] Skipping excluded file: {full_path}")
                continue
            encrypt_in_place(full_path, password)


# === RECURSIVE FOLDER DECRYPTION ===
def decrypt_folder(folder_path, password):
    for root, _, files in os.walk(folder_path):
        for name in files:
            full_path = os.path.join(root, name)
            if is_excluded(full_path):
                print(f"[!] Skipping excluded file: {full_path}")
                continue
            decrypt_in_place(full_path, password)


def clear():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For macOS and Linux
        os.system('clear')


def Startup():
    print("Starting up...")
    print("This shouldn't take long.")
    base_dir = os.path.dirname(__file__)
    settings_path = os.path.join(base_dir, "UserData", "settings.nacprf")
    with open(settings_path, "r") as file:
        SetupCheck = file.read()
    if SetupCheck:
        pass
    else:
        settings_path = os.path.join(base_dir, "UserData", "users.nacprf")
        with open(settings_path, "r") as file:
            name = file.read()
        loop = True
        print(f"Welcome {name}")
        print(f"Enter the password for {name} to continue.")
        while loop:
            verify = input("[?]: ")
            path = os.path.join(base_dir, "UserData")
            decrypt_folder(path, password=verify)
            verify_path = os.path.join(base_dir, "UserData", "passcheck.txt")
            with open(verify_path, "r") as file:
                file_content = file.read().strip()
            if file_content == "True":
                print("Password verified successfully.")
                loop = False
            else:
                print("Password incorrect. Please try again.")
    return verify




def Setup(username, password):
    clear()
    print("Setting up... this may take a minute.")
    base_dir = os.path.dirname(__file__)
    with open("os.nacenv", "w") as file:
        file.write(f"{username}")
    print("Setup complete.")
    print("nacOS will now encrypt one of your folders, retype your password to continue.")
    path = os.path.join(base_dir, "UserData")
    encrypt_folder(path, password=password)
    loop = True
    while loop:
        code = input("Retype your password\n[?]: ")
        decrypt_folder(path, password=code)
        verify_path = os.path.join(base_dir, "UserData", "passcheck.txt")
        with open(verify_path, "r") as file:
            file_content = file.read()
        if file_content:
            print("Password verified successfully.")
            loop = False
        else:
            print("Password is incorrect, Please try again. You may have to reset nacOS if you cannot remember your password.")


def Shutdown(password):
    base_dir = os.path.dirname(__file__)
    path = os.path.join(base_dir, "UserData")
    encrypt_folder(path, password=password)
    print("Shutdown complete.")

def SoftwareCheck():
    base_dir = os.path.dirname(__file__)
    settings_path = os.path.join(base_dir, "UserData", "settings.nacprf")
    with open(settings_path) as file:
        verify_raw = file.read()
        verify_parts = [entry.strip() for entry in verify_raw.split("\n") if entry.strip()]

        # Convert to dict
        verify_settings = {}
        for part in verify_parts:
            if "=" in part:
                key, value = part.split("=", 1)  # Split only on the first "="
                verify_settings[key.strip()] = value.strip()

        if verify_settings["lockdown_software"] == "yes":
            return False

    return True


def MainLoop(password):
    base_dir = os.path.dirname(__file__)
    settings_path = os.path.join(base_dir, "UserData", "settings.nacprf")
    with open(settings_path) as file:
        verify_raw = file.read()
        verify_parts = [entry.strip() for entry in verify_raw.split("\n") if entry.strip()]

        # Convert to dict
        verify_settings = {}
        for part in verify_parts:
            if "=" in part:
                key, value = part.split("=", 1)  # Split only on the first "="
                verify_settings[key.strip()] = value.strip()
        if verify_settings["setup_status"] == "yes":
            SetupStatus = True
        else:
            SetupStatus = False

    if SetupStatus:
        pass
    else:
        print("Setup your account for this Nac")
        usr = input("Username: ")
        code = input("\nPassword: ")
        Setup(usr, code)
    MainLoop = True
    while MainLoop:
        clear()
        print("Welcome to nacOS")
        print("1. Open build information")
        print("2. Shutdown nacOS")
        print("Use the number to select an option.")
        choice = input("[?]: ")
        if choice == "1":
            clear()
            print("Build Information:")
            print(f"Build Version: {BuildVersion} developer beta")
            print("Do not distribute")
            print("Report any bugs as a new issue on the GitHub repository.")
            input("\nPress Enter to return to the main menu...")
            clear()
        elif choice == "2":
            clear()
            print("Shutting down nacOS...")
            clear()
            Shutdown(password)
            MainLoop = False

# ============================================================
# 🔽 HOW TO USE THIS SCRIPT (Windows and macOS friendly)
#
# === On Windows ===
# Example: encrypt_folder(r"D:\NacOS\UserData", password="rice")
#
# === On macOS ===
# Example: encrypt_folder("/Users/yourname/Documents/UserData", password="rice")
#
# === Decrypt same way by changing function ===
# decrypt_folder("your_folder_path_here", password="rice")
#
# === Notes:
# - Make sure Python and `cryptography` are installed (pip install cryptography)
# - You can move this script across platforms — no OS-specific code
# - File extensions are preserved
# - File contents are overwritten — make backups if needed
# - EXCLUDED_FILES contains exact filenames you don't want to encrypt
# ============================================================

# === UNCOMMENT TO RUN ===
# encrypt_folder("path_to_folder", password="your_password_here")
# decrypt_folder("path_to_folder", password="your_password_here")
