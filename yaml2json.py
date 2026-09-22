from __future__ import annotations

import argparse
import json
import sys

import yaml


def yaml_to_json(text: str, compact: bool = False) -> str:
    data = yaml.safe_load(text)
    if compact:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str)
    return json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Konwersja YAML -> JSON.")
    p.add_argument("-i", "--in", dest="infile", default=None, help="plik YAML (domyslnie stdin)")
    p.add_argument("-o", "--out", dest="outfile", default=None, help="plik JSON (domyslnie stdout)")
    p.add_argument("--compact", action="store_true", help="zwarty JSON w jednej linii")
    args = p.parse_args(argv)

    try:
        text = open(args.infile, "r", encoding="utf-8").read() if args.infile else sys.stdin.read()
        out = yaml_to_json(text, args.compact)
    except (yaml.YAMLError, FileNotFoundError, OSError) as exc:
        print(f"Blad: {exc}", file=sys.stderr)
        return 1

    if args.outfile:
        with open(args.outfile, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(out)
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
