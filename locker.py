#!/usr/bin/env python3
"""
SKIPPER'S security - Folder lock & encryption tool
Works on Linux and Windows (cross-platform).

Features:
- Displays banner
- Detects OS and shows OS-specific tips
- Lists files/folders in current directory with indices for selection
- Encrypts selected files/folders (recursively for folders) with a passphrase
- Locks folder structure by encrypting folder names and contents
- Generates a human-readable passphrase from a built-in 30-word list (writes passphrase_list.txt if missing)
- Sends the passphrase to a provided email via SMTP before encrypting (you must provide sender credentials)
- Stores per-run metadata in .skipper_lock_meta.json so it can be decrypted later
- Decrypts when provided the correct passphrase

Dependencies:
  pip install cryptography

Security notes:
- The script derives an encryption key from the passphrase using PBKDF2-HMAC-SHA256 with a random salt (stored in metadata).
- Emailing passphrases can be insecure. Prefer secure channels. Use an app password for Gmail.
- The script replaces original files with encrypted files ending with .locked. A metadata JSON maps originals to encrypted paths.

Use:
  python3 skipper_folder_lock.py

"""

import os
import sys
import json
import base64
import random
import getpass
import smtplib
import time
import platform
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
except Exception as e:
    print("Dependency error: cryptography is required. Install with: pip install cryptography")
    raise

# ---------- Configuration ----------
METADATA_FILENAME = '.skipper_lock_meta.json'
PASSPHRASE_FILE = 'passphrase_list.txt'
PASSPHRASE_WORDS = [
    'ironman', 'captainamerica', 'thor', 'hulk', 'blackwidow', 'hawkeye',
    'spiderman', 'blackpanther', 'doctorstrange', 'scarletwitch', 'vision',
    'falcon', 'wintersoldier', 'war_machine', 'antman', 'wasp', 'captain_marvel',
    'starlord', 'gamora', 'rocket', 'groot', 'drax', 'nebula', 'mantis',
    'loki', 'thanos', 'ultron', 'red-skull', 'wong', 'shuri', 'okoye',
    'valkyrie', 'heimdall', 'odin', 'frigga', 'pepper', 'happy', 'mjolnir',
    'stormbreaker', 'infinity_gauntlet', 'tesseract', 'aether', 'scepter',
    'orb', 'eye-of-agamotto', 'vibranium', 'wakanda', 'asgard', 'sakaar',
    'xandar', 'titan', 'avengers', 'shield', 'hydra', 'quinjet', 'arc_reactor',
    'pym_particles', 'bifrost', 'yondo', 'korg', 'miek', 'howard_the_duck',
    'eternals', 'blade', 'moonknight', 'ms_marvel', 'shehulk', 'ghost_rider'
]
KDF_ITERS = 390_000
BACKEND = default_backend()

# Default sender credentials (replace with your own)
DEFAULT_SENDER_EMAIL = "your senders email"
DEFAULT_SENDER_PASSWORD = " your senders password" # App password for Gmail
DEFAULT_SMTP_SERVER = "smtp.gmail.com"
DEFAULT_SMTP_PORT = 587


# ---------- Utilities ----------

def ensure_passphrase_file_exists():
    p = Path(PASSPHRASE_FILE)
    if not p.exists():
        p.write_text('\n'.join(PASSPHRASE_WORDS))


def read_passphrase_list() -> List[str]:
    ensure_passphrase_file_exists()
    with open(PASSPHRASE_FILE, 'r', encoding='utf-8') as f:
        words = [w.strip() for w in f.readlines() if w.strip()]
    if len(words) < 4:
        raise RuntimeError('passphrase_list.txt must contain at least 4 words')
    return words


def generate_passphrase(num_words: int = 4) -> str:
    words = read_passphrase_list()
    return '-'.join(random.choice(words) for _ in range(num_words))


def derive_key_from_passphrase(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERS,
        backend=BACKEND,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
    return key


# ---------- File system helpers ----------

def list_dir_cwd() -> List[Path]:
    cwd = Path.cwd()
    entries = sorted([p for p in cwd.iterdir()], key=lambda x: (not x.is_dir(), x.name.lower()))
    return entries


def gather_files_and_folders(paths: List[Path]) -> Dict[str, List[Path]]:
    """
    Returns a dictionary with:
    - 'files': list of all files to encrypt
    - 'folders': list of all folders to lock
    """
    result = {'files': [], 'folders': []}

    for p in paths:
        if p.is_file():
            result['files'].append(p)
        elif p.is_dir():
            result['folders'].append(p)
            # Also gather all files within the folder recursively
            for sub in p.rglob('*'):
                if sub.is_file():
                    result['files'].append(sub)
                elif sub.is_dir():
                    result['folders'].append(sub)

    # Remove duplicates and ensure parent folders come before children
    result['folders'] = sorted(list(set(result['folders'])), key=lambda x: (len(x.parts), str(x)))
    result['files'] = list(set(result['files']))

    return result


def encrypt_folder_name(folder_path: Path, fernet: Fernet) -> Path:
    """Encrypt a folder name and rename it"""
    original_name = folder_path.name
    encrypted_name = base64.urlsafe_b64encode(fernet.encrypt(original_name.encode('utf-8'))).decode('utf-8')
    encrypted_path = folder_path.parent / f"{encrypted_name}.locked"

    # Rename the folder
    folder_path.rename(encrypted_path)
    return encrypted_path


def decrypt_folder_name(encrypted_folder_path: Path, fernet: Fernet) -> Path:
    """Decrypt a folder name and rename it back to original"""
    encrypted_name = encrypted_folder_path.name
    if encrypted_name.endswith('.locked'):
        encrypted_name = encrypted_name[:-7]  # Remove .locked extension

    try:
        # Decode the base64 and decrypt
        original_name_bytes = fernet.decrypt(base64.urlsafe_b64decode(encrypted_name))
        original_name = original_name_bytes.decode('utf-8')
        original_path = encrypted_folder_path.parent / original_name

        # Rename back to original
        encrypted_folder_path.rename(original_path)
        return original_path
    except Exception as e:
        print(f"Error decrypting folder name {encrypted_folder_path}: {e}")
        # Fallback: create a decrypted folder with a safe name
        fallback_name = f"decrypted_folder_{encrypted_folder_path.name[:10]}"
        original_path = encrypted_folder_path.parent / fallback_name
        encrypted_folder_path.rename(original_path)
        return original_path


# ---------- Encryption / Decryption ----------

def encrypt_file(path: Path, fernet: Fernet) -> Path:
    data = path.read_bytes()
    token = fernet.encrypt(data)
    encrypted_path = path.with_suffix(path.suffix + '.locked') if path.suffix else Path(str(path) + '.locked')
    encrypted_path.write_bytes(token)
    path.unlink()  # remove original
    return encrypted_path


def decrypt_file(encrypted_path: Path, fernet: Fernet) -> Path:
    token = encrypted_path.read_bytes()
    data = fernet.decrypt(token)
    # remove trailing .locked from filename
    name = str(encrypted_path)
    if name.endswith('.locked'):
        original_name = name[:-7]
    else:
        # fallback
        original_name = name + '.decrypted'
    original_path = Path(original_name)
    original_path.write_bytes(data)
    encrypted_path.unlink()
    return original_path


# ---------- Metadata ----------

def save_metadata(meta: Dict):
    with open(METADATA_FILENAME, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2)


def load_metadata() -> Dict:
    p = Path(METADATA_FILENAME)
    if not p.exists():
        raise FileNotFoundError('Metadata file not found in current directory.')
    with p.open('r', encoding='utf-8') as f:
        return json.load(f)


# ---------- Email sending ----------

def send_passphrase_via_smtp(sender_email: str, sender_password: str, recipient_email: str, passphrase: str,
                             smtp_server: str = DEFAULT_SMTP_SERVER, smtp_port: int = DEFAULT_SMTP_PORT) -> None:
    """
    Sends a simple email containing the passphrase. Caller must supply valid SMTP credentials.
    For Gmail, use an app password and ensure "Less secure app" is not required (use app password with 2FA).
    """
    subject = 'Your SKIPPERS security encryption passphrase'
    current_time = datetime.now(timezone.utc).isoformat()
    body = f"""Hello,

This email contains the passphrase that was generated for your SKIPPERS security encryption run:

Passphrase: {passphrase}

Keep it safe - you will need it to decrypt your files.

Generated: {current_time} UTC

-- Skipper's security thang 😎🌴 """

    # Create message with proper encoding
    message = f"From: {sender_email}\nTo: {recipient_email}\nSubject: {subject}\n\n{body}"

    try:
        server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
        server.ehlo()
        if smtp_port == 587:
            server.starttls()
            server.ehlo()
        server.login(sender_email, sender_password)

        # Encode the message to handle non-ASCII characters properly
        encoded_message = message.encode('utf-8')
        server.sendmail(sender_email, [recipient_email], encoded_message)
        server.quit()
        print(f"✓ Passphrase sent successfully to {recipient_email}")
    except smtplib.SMTPAuthenticationError:
        print("✗ SMTP authentication failed. Check your email credentials.")
        raise
    except smtplib.SMTPException as e:
        print(f"✗ SMTP error occurred: {e}")
        raise
    except Exception as e:
        print(f"✗ Failed to send email: {e}")
        raise


# ---------- UI / CLI ----------

def clear_screen():
    if platform.system().lower().startswith('win'):
        os.system('cls')
    else:
        os.system('clear')


def banner():
    clear_screen()
    print(r"""
##############################################################################################
#                                                                                            #
#     ▗▄▄▖█  ▄ ▄ ▄▄▄▄  ▄▄▄▄  ▗▞▀▚▖ ▄▄▄ ▄▄▄         ▗▖ ▄▄▄  ▗▞▀▘█  ▄ ▗▄▄▄   ▄▄▄  ▄   ▄ ▄▄▄▄   #
#    ▐▌   █▄▀  ▄ █   █ █   █ ▐▛▀▀▘█   ▀▄▄          ▐▌█   █ ▝▚▄▖█▄▀  ▐▌  █ █   █ █ ▄ █ █   █  #
#     ▝▀▚▖█ ▀▄ █ █▄▄▄▀ █▄▄▄▀ ▝▚▄▄▖█   ▄▄▄▀         ▐▌▀▄▄▄▀     █ ▀▄ ▐▌  █ ▀▄▄▄▀ █▄█▄█ █   █  #
#    ▗▄▄▞▘█  █ █ █     █                           ▐▙▄▄▖       █  █ ▐▙▄▄▀                    #
#           ▀     ▀                                                                          #
#                                                                                            #
#  - Folder and File Lock!!!                                                                             #
# ############################################################################################
    """)
    print(f"Detected OS: {platform.system()} ({platform.platform()})\n")


def show_main_menu():
    print('Options:')
    print('  1) Lock & Encrypt files/folders')
    print('  2) Unlock & Decrypt (provide passphrase)')
    print('  3) Exit')


def choose_from_cwd() -> List[Path]:
    entries = list_dir_cwd()
    if not entries:
        print('No files or folders in current directory.')
        return []
    print('\nItems in current directory:')
    for i, e in enumerate(entries, 1):
        t = '<DIR>' if e.is_dir() else '<FILE>'
        size = f" ({e.stat().st_size} bytes)" if e.is_file() else ""
        print(f"  {i}) {t} {e.name}{size}")
    print('\nEnter a comma-separated list of indices to select items to lock (e.g. 1,3,4)')
    s = input('Selection: ').strip()
    if not s:
        return []
    chosen = []
    for part in s.split(','):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(entries):
                chosen.append(entries[idx])
        except ValueError:
            continue
    return chosen


def confirm_choice(paths: List[Path]) -> bool:
    print('\nYou selected these files/folders to lock/encrypt:')
    for p in paths:
        item_type = "FOLDER" if p.is_dir() else "FILE"
        print(f"  - [{item_type}] {str(p)}")
    print('\nWARNING: Original files and folders will be encrypted and renamed!')
    print('Proceed? (y/N)')
    c = input('> ').strip().lower()
    return c == 'y' or c == 'yes'


def lock_and_encrypt():
    print('\n--- LOCK & ENCRYPT ---\n')
    selected = choose_from_cwd()
    if not selected:
        print('No selection made, returning to menu.')
        return
    if not confirm_choice(selected):
        print('Cancelled.')
        return

    recipient_email = input('\nEnter an email to send the passphrase to (recipient): ').strip()

    print('\nSMTP Configuration:')
    print(f'Default sender: {DEFAULT_SENDER_EMAIL}')
    use_default = input('Use default sender credentials? (Y/n): ').strip().lower()

    if use_default in ('', 'y', 'yes'):
        sender_email = DEFAULT_SENDER_EMAIL
        sender_password = DEFAULT_SENDER_PASSWORD
        smtp_server = DEFAULT_SMTP_SERVER
        smtp_port = DEFAULT_SMTP_PORT
    else:
        sender_email = input('Sender email (e.g. you@gmail.com): ').strip()
        sender_password = getpass.getpass('Sender email password (or app password): ')
        smtp_server = input(f'SMTP server (default {DEFAULT_SMTP_SERVER}): ').strip() or DEFAULT_SMTP_SERVER
        smtp_port_input = input(f'SMTP port (default {DEFAULT_SMTP_PORT}): ').strip()
        smtp_port = int(smtp_port_input) if smtp_port_input else DEFAULT_SMTP_PORT

    passphrase = generate_passphrase()

    # Display passphrase locally as backup
    print(f'\nGenerated Passphrase: {passphrase}')
    print('IMPORTANT: Save this passphrase in a secure location!')

    # Send passphrase via email
    try:
        print(f'\nSending passphrase to {recipient_email}...')
        send_passphrase_via_smtp(sender_email, sender_password, recipient_email, passphrase, smtp_server, smtp_port)
    except Exception as e:
        print(f'Failed to send passphrase via SMTP: {e}')
        print('Do you want to continue without sending the passphrase? (y/N)')
        if input('> ').strip().lower() not in ('y', 'yes'):
            print('Aborting operation.')
            return

    # Prepare salt and key
    salt = os.urandom(16)
    key = derive_key_from_passphrase(passphrase, salt)
    fernet = Fernet(key)

    # Gather files and folders
    items = gather_files_and_folders(selected)
    all_files = items['files']
    all_folders = items['folders']

    if not all_files and not all_folders:
        print('No files or folders found under selected paths.')
        return

    metadata = {
        'created_at': datetime.now(timezone.utc).isoformat(),
        'os': platform.system(),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'passphrase_hint': '-'.join(passphrase.split('-')[:1]) + '-... (hidden)',
        'files': [],
        'folders': []
    }

    print(f'\nEncrypting {len(all_files)} files and locking {len(all_folders)} folders...')

    # First encrypt all files
    successful_file_encryptions = 0
    for f in all_files:
        try:
            enc_path = encrypt_file(f, fernet)
            metadata['files'].append({'original': str(f), 'encrypted': str(enc_path)})
            print(f'✓ Encrypted file: {f} -> {enc_path}')
            successful_file_encryptions += 1
        except Exception as e:
            print(f'✗ Failed to encrypt file {f}: {e}')

    # Then lock folders (process from deepest to shallowest to avoid path issues)
    successful_folder_locks = 0
    for folder in reversed(all_folders):
        try:
            # Check if folder still exists (might have been renamed as part of parent folder)
            if folder.exists():
                enc_folder_path = encrypt_folder_name(folder, fernet)
                metadata['folders'].append({'original': str(folder), 'encrypted': str(enc_folder_path)})
                print(f'✓ Locked folder: {folder} -> {enc_folder_path}')
                successful_folder_locks += 1
        except Exception as e:
            print(f'✗ Failed to lock folder {folder}: {e}')

    save_metadata(metadata)
    print(f'\nEncryption complete!')
    print(f'  - {successful_file_encryptions}/{len(all_files)} files encrypted')
    print(f'  - {successful_folder_locks}/{len(all_folders)} folders locked')
    print('Metadata saved to', METADATA_FILENAME)
    print('Keep the passphrase safe!')


def unlock_and_decrypt():
    print('\n--- UNLOCK & DECRYPT ---\n')
    try:
        meta = load_metadata()
    except Exception as e:
        print('Error loading metadata:', e)
        return

    print('Loaded metadata created at', meta.get('created_at'))
    print('Encrypted files found:', len(meta.get('files', [])))
    print('Locked folders found:', len(meta.get('folders', [])))

    # Prompt for passphrase
    passphrase = getpass.getpass('Enter the passphrase you received by email: ')

    try:
        salt = base64.b64decode(meta['salt'])
        key = derive_key_from_passphrase(passphrase, salt)
        fernet = Fernet(key)
    except Exception as e:
        print(f'Error deriving key: {e}')
        print('Invalid passphrase or corrupted metadata.')
        return

    failed_files = []
    successful_file_decryptions = 0

    failed_folders = []
    successful_folder_unlocks = 0

    # First unlock folders (process from shallowest to deepest to avoid path issues)
    for folder_item in meta.get('folders', []):
        enc_folder_path = Path(folder_item['encrypted'])
        if not enc_folder_path.exists():
            print(f'✗ Locked folder not found: {enc_folder_path}')
            failed_folders.append(str(enc_folder_path))
            continue
        try:
            orig_folder = decrypt_folder_name(enc_folder_path, fernet)
            print(f'✓ Unlocked folder: {enc_folder_path} -> {orig_folder}')
            successful_folder_unlocks += 1
        except Exception as e:
            print(f'✗ Failed to unlock folder {enc_folder_path}: {e}')
            failed_folders.append(str(enc_folder_path))

    # Then decrypt files
    for file_item in meta.get('files', []):
        enc_file_path = Path(file_item['encrypted'])
        if not enc_file_path.exists():
            print(f'✗ Encrypted file not found: {enc_file_path}')
            failed_files.append(str(enc_file_path))
            continue
        try:
            orig_file = decrypt_file(enc_file_path, fernet)
            print(f'✓ Decrypted file: {enc_file_path} -> {orig_file}')
            successful_file_decryptions += 1
        except Exception as e:
            print(f'✗ Failed to decrypt file {enc_file_path}: {e}')
            failed_files.append(str(enc_file_path))

    if failed_files or failed_folders:
        print(f'\nWarning:')
        if failed_files:
            print(f'  - {len(failed_files)} files failed to decrypt')
        if failed_folders:
            print(f'  - {len(failed_folders)} folders failed to unlock')
        print('Check passphrase and file integrity.')
    else:
        # Remove metadata if all decrypted cleanly
        try:
            os.remove(METADATA_FILENAME)
            print(f'\n✓ All items decrypted successfully!')
            print(f'  - {successful_file_decryptions} files decrypted')
            print(f'  - {successful_folder_unlocks} folders unlocked')
            print('Removed metadata file', METADATA_FILENAME)
        except Exception as e:
            print(f'Note: Could not remove metadata file: {e}')


def main():
    ensure_passphrase_file_exists()
    while True:
        try:
            banner()
            show_main_menu()
            c = input('\nChoose option (1/2/3): ').strip()
            if c == '1':
                lock_and_encrypt()
                input('\nPress Enter to return to menu...')
            elif c == '2':
                unlock_and_decrypt()
                input('\nPress Enter to return to menu...')
            elif c == '3':
                print('Goodbye!')
                break
            else:
                print('Invalid choice.')
                time.sleep(1)
        except KeyboardInterrupt:
            print('\n\nOperation cancelled by user.')
            break
        except Exception as e:
            print(f'\nAn error occurred: {e}')
            input('Press Enter to continue...')


if __name__ == '__main__':
    main()