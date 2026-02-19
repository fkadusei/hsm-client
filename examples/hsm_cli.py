from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in (None, ""):
    repo_root = Path(__file__).resolve().parents[1]
    repo_src = repo_root / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))
    # Ensure sibling example modules are importable for dispatch.
    examples_dir = Path(__file__).resolve().parent
    if str(examples_dir) not in sys.path:
        sys.path.insert(0, str(examples_dir))


class _HelpFormatter(
    argparse.RawTextHelpFormatter,
    argparse.ArgumentDefaultsHelpFormatter,
):
    """Readable top-level help with examples and defaults."""


HELP_EPILOG = """Examples:
  # Symmetric encrypt/decrypt using the unified CLI
  python3 examples/hsm_cli.py --mode symmetric --message "hello symmetric" --out payload.json
  python3 examples/hsm_cli.py --mode symmetric --decrypt --payload-file payload.json

  # PKI key/cert/sign workflows using the same file
  python3 examples/hsm_cli.py --mode pki keygen --profile ca_root --private-label root-ca-key --ceremony-reference CEREMONY-2026Q1
  python3 examples/hsm_cli.py --mode pki cert sign --cert-type root --issuer-private-label root-ca-key --subject-cn "Example Root CA" --ceremony-reference CEREMONY-2026Q1 --out root-ca.pem
  python3 examples/hsm_cli.py --mode pki sign --private-label app-signing-key --message "payload" --out detached-signature.json

Tip:
  Show mode-specific help through the single file:
    python3 examples/hsm_cli.py --mode symmetric --help
    python3 examples/hsm_cli.py --mode pki --help
    python3 examples/hsm_cli.py --mode symmetric -- --help
    python3 examples/hsm_cli.py --mode pki -- --help
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Unified HSM application CLI. "
            "Use --mode symmetric for AES data operations or --mode pki for key/cert/sign workflows."
        ),
        formatter_class=_HelpFormatter,
        epilog=HELP_EPILOG,
        add_help=False,
    )
    parser.add_argument(
        "-h",
        "--help",
        action="store_true",
        help="Show top-level help or mode-specific help when --mode is set.",
    )
    parser.add_argument(
        "--mode",
        choices=("symmetric", "pki"),
        help="Application mode to run.",
    )
    return parser


def _strip_separator(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    argv = list(sys.argv[1:] if argv is None else argv)
    args, forwarded = parser.parse_known_args(argv)
    forwarded = _strip_separator(forwarded)

    if args.help and args.mode is None:
        parser.print_help()
        return 0

    if args.mode is None:
        parser.error("the following arguments are required: --mode")

    if args.help and not forwarded:
        # Route help directly to the selected mode, e.g.:
        # python3 examples/hsm_cli.py --mode symmetric --help
        forwarded = ["--help"]

    if args.mode == "symmetric":
        from basic_flow import main as symmetric_main

        return symmetric_main(forwarded)

    from pki_cli import main as pki_main

    return pki_main(forwarded)


if __name__ == "__main__":
    raise SystemExit(main())
