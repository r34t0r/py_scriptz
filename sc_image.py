from __future__ import annotations

import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import file
import image


def _passwords(args: argparse.Namespace, confirm: bool) -> tuple[bytes, bytes]:
    crypto_pwd = args.crypto_password
    stego_pwd = args.stego_password
    if crypto_pwd is None or stego_pwd is None:
        shared = args.password
        if shared is None and (crypto_pwd is None or stego_pwd is None):
            shared = getpass.getpass("Haslo: ")
            if confirm:
                if shared != getpass.getpass("Powtorz haslo: "):
                    raise SystemExit("Hasla sie roznia - przerwano.")
            if not shared:
                raise SystemExit("Puste haslo - przerwano.")
        crypto_pwd = crypto_pwd if crypto_pwd is not None else shared
        stego_pwd = stego_pwd if stego_pwd is not None else shared
    return crypto_pwd.encode("utf-8"), stego_pwd.encode("utf-8")


def cmd_pack(args: argparse.Namespace) -> int:
    with open(args.infile, "rb") as fh:
        data = fh.read()
    crypto_pwd, stego_pwd = _passwords(args, confirm=True)
    blob = file.encrypt_bytes(data, crypto_pwd)
    image.hide(args.carrier, blob, args.outfile, stego_pwd)
    print(
        f"OK: {args.infile} ({len(data)} B) -> zaszyfrowano ({len(blob)} B) "
        f"-> ukryto w {args.outfile}"
    )
    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    crypto_pwd, stego_pwd = _passwords(args, confirm=False)
    blob = image.extract_bytes(args.carrier, stego_pwd)
    data = file.decrypt_bytes(blob, crypto_pwd)
    with open(args.outfile, "wb") as fh:
        fh.write(data)
    print(f"OK: {args.carrier} -> wydobyto ({len(blob)} B) -> odszyfrowano -> {args.outfile} ({len(data)} B)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Szyfrowanie + steganografia PNG w jednej komendzie.")
    sub = p.add_subparsers(dest="command", required=True)

    pk = sub.add_parser("pack", help="zaszyfruj plik i ukryj w obrazie")
    pk.add_argument("-i", "--in", dest="infile", required=True, help="plik tekstowy do ukrycia")
    pk.add_argument("-c", "--carrier", required=True, help="obraz-nosnik (wejscie)")
    pk.add_argument("-o", "--out", dest="outfile", required=True, help="wyjsciowy PNG ze schowana trescia")
    pk.set_defaults(func=cmd_pack)

    up = sub.add_parser("unpack", help="wydobadz z obrazu i odszyfruj")
    up.add_argument("-c", "--carrier", required=True, help="PNG ze schowana trescia")
    up.add_argument("-o", "--out", dest="outfile", required=True, help="odzyskany plik tekstowy")
    up.set_defaults(func=cmd_unpack)

    for sp in (pk, up):
        sp.add_argument("-p", "--password", default=None, help="wspolne haslo dla obu warstw")
        sp.add_argument("--crypto-password", default=None, help="osobne haslo warstwy szyfrujacej")
        sp.add_argument("--stego-password", default=None, help="osobne haslo warstwy steganograficznej")
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
