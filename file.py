from __future__ import annotations

import argparse
import getpass
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"SCF1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1


def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password)


def encrypt_bytes(plaintext: bytes, password: bytes) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)
    return MAGIC + salt + nonce + ct


def decrypt_bytes(blob: bytes, password: bytes) -> bytes:
    head = len(MAGIC) + SALT_LEN + NONCE_LEN
    if len(blob) < head + 16:
        raise ValueError("Plik za krotki lub to nie jest kontener SCF1.")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("Brak sygnatury SCF1 - to nie jest plik z tego skryptu.")
    off = len(MAGIC)
    salt = blob[off : off + SALT_LEN]; off += SALT_LEN
    nonce = blob[off : off + NONCE_LEN]; off += NONCE_LEN
    ct = blob[off:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ct, None)
    except Exception as exc:
        raise ValueError("Odszyfrowanie nie powiodlo sie (zle haslo lub uszkodzony plik).") from exc


def read_password(args: argparse.Namespace, confirm: bool) -> bytes:
    if args.password is not None:
        return args.password.encode("utf-8")
    if args.password_file is not None:
        with open(args.password_file, "r", encoding="utf-8") as fh:
            return fh.readline().rstrip("\n").encode("utf-8")
    pwd = getpass.getpass("Haslo: ")
    if confirm:
        again = getpass.getpass("Powtorz haslo: ")
        if pwd != again:
            raise SystemExit("Hasla sie roznia - przerwano.")
    if not pwd:
        raise SystemExit("Puste haslo - przerwano.")
    return pwd.encode("utf-8")


def cmd_encrypt(args: argparse.Namespace) -> int:
    with open(args.infile, "rb") as fh:
        data = fh.read()
    password = read_password(args, confirm=True)
    blob = encrypt_bytes(data, password)
    with open(args.outfile, "wb") as fh:
        fh.write(blob)
    print(f"Zaszyfrowano: {args.infile} ({len(data)} B) -> {args.outfile} ({len(blob)} B)")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    with open(args.infile, "rb") as fh:
        blob = fh.read()
    password = read_password(args, confirm=False)
    data = decrypt_bytes(blob, password)
    with open(args.outfile, "wb") as fh:
        fh.write(data)
    print(f"Odszyfrowano: {args.infile} ({len(blob)} B) -> {args.outfile} ({len(data)} B)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Szyfrowanie plikow tekstowych (AES-256-GCM, klucz z hasla przez scrypt).")
    sub = p.add_subparsers(dest="command", required=True)
    for name, func in (("encrypt", cmd_encrypt), ("decrypt", cmd_decrypt)):
        sp = sub.add_parser(name, help=f"{name} pliku")
        sp.add_argument("-i", "--in", dest="infile", required=True, help="plik wejsciowy")
        sp.add_argument("-o", "--out", dest="outfile", required=True, help="plik wyjsciowy")
        sp.add_argument("-p", "--password", default=None, help="haslo (jesli brak - zapyta interaktywnie)")
        sp.add_argument("--password-file", default=None, help="plik z haslem (pierwsza linia)")
        sp.set_defaults(func=func)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"Blad: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
