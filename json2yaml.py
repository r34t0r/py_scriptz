from __future__ import annotations

import argparse
import json
import sys

import yaml


def json_to_yaml(text: str) -> str:
    data = json.loads(text)
    return yaml.safe_dump(
        data,
        allow_unicode=True,
        sort_keys=False,
        default_flow_style=False,
        width=1_000_000,
        indent=2,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Konwersja JSON -> YAML.")
    p.add_argument("-i", "--in", dest="infile", default=None, help="plik JSON (domyslnie stdin)")
    p.add_argument("-o", "--out", dest="outfile", default=None, help="plik YAML (domyslnie stdout)")
    args = p.parse_args(argv)

    try:
        text = open(args.infile, "r", encoding="utf-8").read() if args.infile else sys.stdin.read()
        out = json_to_yaml(text)
    except (json.JSONDecodeError, FileNotFoundError, OSError) as exc:
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
