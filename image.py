from __future__ import annotations

import argparse
import getpass
import random
import sys
from array import array

from PIL import Image
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"ST01"
VERSION = 1
LEN_BYTES = 4

_SEED_SALT = b"stego-lsb-perm-v1"
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1


def _seed_from_password(password: bytes) -> int:
    kdf = Scrypt(salt=_SEED_SALT, length=32, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return int.from_bytes(kdf.derive(password), "big")


class _Order:

    def __init__(self, total: int, seed: int | None):
        self.total = total
        self.i = 0
        if seed is None:
            self.arr = None
            self.rng = None
        else:
            self.arr = array("I", range(total))
            self.rng = random.Random(seed)

    def next(self) -> int:
        if self.i >= self.total:
            raise ValueError("Za malo miejsca w obrazie na wiadomosc.")
        if self.arr is None:
            pos = self.i
        else:
            j = self.rng.randint(self.i, self.total - 1)
            self.arr[self.i], self.arr[j] = self.arr[j], self.arr[self.i]
            pos = self.arr[self.i]
        self.i += 1
        return pos


def _bits(data: bytes):
    for byte in data:
        for shift in range(7, -1, -1):
            yield (byte >> shift) & 1


def _load_rgb(path: str) -> Image.Image:
    img = Image.open(path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return img


def hide(carrier_path: str, data: bytes, out_path: str, password: bytes | None) -> None:
    img = _load_rgb(carrier_path)
    buf = bytearray(img.tobytes())
    total = len(buf)

    if password is None:
        preamble = MAGIC + bytes([VERSION]) + len(data).to_bytes(LEN_BYTES, "big")
    else:
        preamble = len(data).to_bytes(LEN_BYTES, "big")
    payload = preamble + data

    need_bits = len(payload) * 8
    if need_bits > total:
        raise ValueError(
            f"Wiadomosc za duza: potrzeba {need_bits} bitow, obraz ma {total} "
            f"(pojemnosc ~{total // 8} B). Uzyj wiekszego nosnika."
        )

    seed = _seed_from_password(password) if password is not None else None
    order = _Order(total, seed)
    for bit in _bits(payload):
        pos = order.next()
        buf[pos] = (buf[pos] & 0xFE) | bit

    out = Image.frombytes("RGB", img.size, bytes(buf))
    out.save(out_path, format="PNG")


def _read_bits(buf: bytes, order: _Order, nbits: int) -> bytes:
    out = bytearray((nbits + 7) // 8)
    for k in range(nbits):
        bit = buf[order.next()] & 1
        out[k >> 3] |= bit << (7 - (k & 7))
    return bytes(out)


def extract_bytes(stego_path: str, password: bytes | None) -> bytes:
    img = _load_rgb(stego_path)
    buf = img.tobytes()
    total = len(buf)
    seed = _seed_from_password(password) if password is not None else None
    order = _Order(total, seed)

    if password is None:
        head = _read_bits(buf, order, (len(MAGIC) + 1 + LEN_BYTES) * 8)
        if head[: len(MAGIC)] != MAGIC:
            raise ValueError("Brak ukrytej wiadomosci (zla sygnatura) lub uzyto trybu z haslem.")
        length = int.from_bytes(head[len(MAGIC) + 1 :], "big")
    else:
        length = int.from_bytes(_read_bits(buf, order, LEN_BYTES * 8), "big")

    if length <= 0 or (order.i + length * 8) > total:
        raise ValueError("Nie znaleziono poprawnej wiadomosci (zle haslo/tryb lub czysty obraz).")

    return _read_bits(buf, order, length * 8)


def extract(stego_path: str, out_path: str, password: bytes | None) -> bytes:
    data = extract_bytes(stego_path, password)
    with open(out_path, "wb") as fh:
        fh.write(data)
    return data


def _get_password(args: argparse.Namespace) -> bytes | None:
    if args.password is not None:
        return args.password.encode("utf-8")
    if getattr(args, "ask_password", False):
        pwd = getpass.getpass("Haslo steganografii: ")
        if not pwd:
            raise SystemExit("Puste haslo - przerwano.")
        return pwd.encode("utf-8")
    return None


def cmd_hide(args: argparse.Namespace) -> int:
    with open(args.data, "rb") as fh:
        data = fh.read()
    password = _get_password(args)
    hide(args.carrier, data, args.outfile, password)
    mode = "kluczowany" if password is not None else "sekwencyjny"
    print(f"Ukryto {len(data)} B w {args.outfile} (tryb: {mode}).")
    return 0


def cmd_extract(args: argparse.Namespace) -> int:
    password = _get_password(args)
    data = extract(args.carrier, args.outfile, password)
    print(f"Wydobyto {len(data)} B -> {args.outfile}.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Steganografia LSB w PNG (ukrywanie/wydobywanie pliku).")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hide", help="ukryj plik w obrazie")
    h.add_argument("-c", "--carrier", required=True, help="obraz-nosnik (PNG/JPG/... wejscie)")
    h.add_argument("-d", "--data", required=True, help="plik do ukrycia")
    h.add_argument("-o", "--out", dest="outfile", required=True, help="wyjsciowy PNG")
    h.set_defaults(func=cmd_hide)

    e = sub.add_parser("extract", help="wydobadz plik z obrazu")
    e.add_argument("-c", "--carrier", required=True, help="obraz ze stego (PNG)")
    e.add_argument("-o", "--out", dest="outfile", required=True, help="wyjsciowy plik z danymi")
    e.set_defaults(func=cmd_extract)

    for sp in (h, e):
        sp.add_argument("-p", "--password", default=None, help="haslo (tryb kluczowany, rozrzucanie bitow)")
        sp.add_argument("--ask-password", action="store_true", help="zapytaj o haslo interaktywnie")
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
