# Secure CLI Password Manager

This is a simple and secure command-line password manager built in Python.

## Features
- AES-256-GCM encryption for all credentials
- Master password protection with PBKDF2 key derivation
- JSON-based encrypted storage
- CRUD operations: add, list, get, update, delete entries
- Change master password securely

## Requirements
- Python 3.8+
- cryptography library

Install dependencies:
```bash
pip install cryptography
```

## Usage

Initialize vault:
```bash
python vault.py init --file vault.json
```

Add entry:
```bash
python vault.py add --file vault.json
```

List entries:
```bash
python vault.py list --file vault.json
```

Get entry by ID:
```bash
python vault.py get --file vault.json --id <entry-id>
```

Update entry:
```bash
python vault.py update --file vault.json --id <entry-id>
```

Delete entry:
```bash
python vault.py delete --file vault.json --id <entry-id>
```

Change master password:
```bash
python vault.py changemaster --file vault.json
```

## Notes
- All data remains encrypted at rest using AES-256-GCM.
- Master password is never stored, only derived into a key when needed.
- Store `vault.json` securely and back it up safely.
