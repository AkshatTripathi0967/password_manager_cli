import argparse
import base64
import json
import os
import secrets
import sys
import uuid
from getpass import getpass
from typing import Dict, Any, List

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ========== Configuration ==========
KDF_ITERATIONS = 200_000
KEY_LEN = 32  # 32 bytes = 256 bits
SALT_LEN = 16
NONCE_LEN = 12  # recommended for AESGCM
# ===================================

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode('utf-8')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('utf-8'))

def derive_master_key(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password_bytes)

def encrypt_entry(master_key: bytes, plaintext_obj: Dict[str, Any]) -> Dict[str, str]:
    """
    Encrypt a Python dict (plaintext_obj) and return a dict with base64 ciphertext and nonce.
    """
    aesgcm = AESGCM(master_key)
    nonce = secrets.token_bytes(NONCE_LEN)
    plaintext = json.dumps(plaintext_obj, separators=(',', ':')).encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": b64(nonce), "ct": b64(ciphertext)}

def decrypt_entry(master_key: bytes, encrypted: Dict[str, str]) -> Dict[str, Any]:
    aesgcm = AESGCM(master_key)
    nonce = ub64(encrypted['nonce'])
    ct = ub64(encrypted['ct'])
    plaintext = aesgcm.decrypt(nonce, ct, associated_data=None)
    return json.loads(plaintext.decode('utf-8'))

def init_vault(path: str) -> None:
    if os.path.exists(path):
        print(f"File '{path}' already exists. Aborting to avoid overwrite.")
        sys.exit(1)
    master = getpass("Create master password: ")
    confirm = getpass("Confirm master password: ")
    if master != confirm:
        print("Passwords do not match. Aborting.")
        sys.exit(1)
    salt = secrets.token_bytes(SALT_LEN)
    # We do not store the master key; we store salt and entries
    vault = {
        "kdf_salt": b64(salt),
        "kdf_iterations": KDF_ITERATIONS,
        "entries": []  # list of {id, data: {nonce, ct}}
    }
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(vault, f, indent=2)
    print(f"Initialized new vault at '{path}'.")

def load_vault(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        print(f"Vault file '{path}' does not exist. Use 'init' to create one.")
        sys.exit(1)
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_vault(path: str, vault: Dict[str, Any]) -> None:
    # write atomically
    tmp = path + ".tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(vault, f, indent=2)
    os.replace(tmp, path)

def get_master_key_from_vault(vault: Dict[str, Any]) -> bytes:
    salt = ub64(vault['kdf_salt'])
    iterations = int(vault.get('kdf_iterations', KDF_ITERATIONS))
    master = getpass("Enter master password: ")
    # derive key
    try:
        k = derive_master_key(master, salt)
    except Exception:
        print("Failed deriving key.")
        sys.exit(1)
    return k

def add_entry(path: str) -> None:
    vault = load_vault(path)
    master_key = get_master_key_from_vault(vault)

    site = input("Site (e.g. example.com): ").strip()
    username = input("Username: ").strip()
    password = getpass("Password (leave blank to generate one): ").strip()
    if password == "":
        # generate a secure password
        password = b64(secrets.token_bytes(12))  # base64 ~16 chars
        print(f"Generated password: {password}")

    notes = input("Notes (optional): ").strip()
    entry_obj = {
        "site": site,
        "username": username,
        "password": password,
        "notes": notes
    }
    enc = encrypt_entry(master_key, entry_obj)
    entry = {
        "id": str(uuid.uuid4()),
        "data": enc
    }
    vault['entries'].append(entry)
    save_vault(path, vault)
    print(f"Entry added with id {entry['id']}")

def list_entries(path: str, show_all=False) -> None:
    vault = load_vault(path)
    master_key = get_master_key_from_vault(vault)
    entries = vault.get('entries', [])
    if not entries:
        print("No entries in vault.")
        return
    print("Entries:")
    for e in entries:
        try:
            dec = decrypt_entry(master_key, e['data'])
            sid = e.get('id', '<no-id>')
            site = dec.get('site', '<unknown>')
            username = dec.get('username', '')
            if show_all:
                print(f"- id: {sid}\n  site: {site}\n  username: {username}\n  password: {dec.get('password')}\n  notes: {dec.get('notes')}\n")
            else:
                print(f"- id: {sid} | site: {site} | username: {username}")
        except Exception as ex:
            print(f"- id: {e.get('id','<no-id>')} | <decryption failed>")

def get_entry(path: str, entry_id: str) -> None:
    vault = load_vault(path)
    master_key = get_master_key_from_vault(vault)
    entries = vault.get('entries', [])
    for e in entries:
        if e.get('id') == entry_id:
            try:
                dec = decrypt_entry(master_key, e['data'])
            except Exception:
                print("Decryption failed. Wrong master password or data corrupted.")
                sys.exit(1)
            print(f"ID: {entry_id}")
            print(f"Site: {dec.get('site')}")
            print(f"Username: {dec.get('username')}")
            print(f"Password: {dec.get('password')}")
            print(f"Notes: {dec.get('notes')}")
            return
    print(f"No entry with id {entry_id}")

def delete_entry(path: str, entry_id: str) -> None:
    vault = load_vault(path)
    master_key = get_master_key_from_vault(vault)
    entries = vault.get('entries', [])
    new_entries = [e for e in entries if e.get('id') != entry_id]
    if len(new_entries) == len(entries):
        print(f"No entry with id {entry_id}")
        return
    vault['entries'] = new_entries
    save_vault(path, vault)
    print(f"Deleted entry {entry_id}")

def update_entry(path: str, entry_id: str) -> None:
    vault = load_vault(path)
    master_key = get_master_key_from_vault(vault)
    entries = vault.get('entries', [])
    for i, e in enumerate(entries):
        if e.get('id') == entry_id:
            try:
                dec = decrypt_entry(master_key, e['data'])
            except Exception:
                print("Decryption failed. Wrong master password or data corrupted.")
                sys.exit(1)
            print("Leave fields blank to keep existing values.")
            site = input(f"Site [{dec.get('site')}]: ").strip() or dec.get('site')
            username = input(f"Username [{dec.get('username')}]: ").strip() or dec.get('username')
            password = getpass("Password (leave blank to keep existing): ").strip() or dec.get('password')
            notes = input(f"Notes [{dec.get('notes','')}]: ").strip() or dec.get('notes')
            new_obj = {"site": site, "username": username, "password": password, "notes": notes}
            entries[i]['data'] = encrypt_entry(master_key, new_obj)
            vault['entries'] = entries
            save_vault(path, vault)
            print(f"Updated entry {entry_id}")
            return
    print(f"No entry with id {entry_id}")

def change_master_password(path: str) -> None:
    vault = load_vault(path)
    old_master_key = get_master_key_from_vault(vault)
    # decrypt all entries
    entries = vault.get('entries', [])
    decrypted_objs = []
    for e in entries:
        try:
            decrypted_objs.append((e['id'], decrypt_entry(old_master_key, e['data'])))
        except Exception:
            print("Decryption failed for an entry — aborting change of master password.")
            sys.exit(1)
    # ask for new master
    new_master = getpass("Enter new master password: ")
    confirm = getpass("Confirm new master password: ")
    if new_master != confirm:
        print("Passwords do not match. Aborting.")
        sys.exit(1)
    new_salt = secrets.token_bytes(SALT_LEN)
    new_key = derive_master_key(new_master, new_salt)
    # re-encrypt all entries with new key and new nonces
    new_entries = []
    for eid, obj in decrypted_objs:
        new_entries.append({"id": eid, "data": encrypt_entry(new_key, obj)})
    vault['kdf_salt'] = b64(new_salt)
    vault['kdf_iterations'] = KDF_ITERATIONS
    vault['entries'] = new_entries
    save_vault(path, vault)
    print("Master password changed and vault re-encrypted.")

def parse_args():
    p = argparse.ArgumentParser(description="Simple encrypted password manager (AES-256-GCM).")
    sub = p.add_subparsers(dest='cmd', required=True)

    sp_init = sub.add_parser('init', help='Initialize a new vault')
    sp_init.add_argument('--file', required=True, help='Vault JSON file path')

    sp_add = sub.add_parser('add', help='Add a new credential entry')
    sp_add.add_argument('--file', required=True, help='Vault JSON file path')

    sp_list = sub.add_parser('list', help='List entries (ID, site, username)')
    sp_list.add_argument('--file', required=True, help='Vault JSON file path')
    sp_list.add_argument('--all', action='store_true', help='Show all fields (dangerous on shared screens)')

    sp_get = sub.add_parser('get', help='Get entry details by id')
    sp_get.add_argument('--file', required=True, help='Vault JSON file path')
    sp_get.add_argument('--id', required=True, help='Entry id')

    sp_update = sub.add_parser('update', help='Update an entry')
    sp_update.add_argument('--file', required=True, help='Vault JSON file path')
    sp_update.add_argument('--id', required=True, help='Entry id')

    sp_delete = sub.add_parser('delete', help='Delete an entry')
    sp_delete.add_argument('--file', required=True, help='Vault JSON file path')
    sp_delete.add_argument('--id', required=True, help='Entry id')

    sp_chg = sub.add_parser('changemaster', help='Change master password')
    sp_chg.add_argument('--file', required=True, help='Vault JSON file path')

    return p.parse_args()

def main():
    args = parse_args()
    cmd = args.cmd
    path = getattr(args, 'file', None)

    if cmd == 'init':
        init_vault(path)
    elif cmd == 'add':
        add_entry(path)
    elif cmd == 'list':
        list_entries(path, show_all=args.all)
    elif cmd == 'get':
        get_entry(path, args.id)
    elif cmd == 'delete':
        delete_entry(path, args.id)
    elif cmd == 'update':
        update_entry(path, args.id)
    elif cmd == 'changemaster':
        change_master_password(path)
    else:
        print("Unknown command")

if __name__ == '__main__':
    main()
