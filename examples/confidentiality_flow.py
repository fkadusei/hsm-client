from __future__ import annotations

import argparse
import base64
import sys
from pathlib import Path

if __package__ in (None, ""):
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

try:
    from hsm_client import (
        HsmConfig,
        HsmClientError,
        Pkcs11HsmClient,
        configure_logging,
    )
except ModuleNotFoundError as exc:
    if exc.name == "pkcs11":
        raise SystemExit(
            "Missing dependency: python-pkcs11\n"
            "Install it with:\n"
            "  python3 -m pip install -e .\n"
            "or:\n"
            "  python3 -m pip install python-pkcs11"
        ) from exc
    raise


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Confidentiality demo using asymmetric encryption "
            "(public key encrypt, private key decrypt)."
        )
    )
    parser.add_argument(
        "--private-label",
        default="app-confidentiality-rsa",
        help="Private key label (default: app-confidentiality-rsa).",
    )
    parser.add_argument(
        "--public-label",
        default=None,
        help="Public key label (default: <private-label>.pub).",
    )
    parser.add_argument(
        "--algorithm",
        default="rsa_oaep_sha1",
        help=(
            "Confidentiality algorithm. Examples: rsa_oaep_sha1, "
            "rsa_oaep_sha256, rsa_pkcs1v15."
        ),
    )
    parser.add_argument(
        "--message",
        default="confidential payload",
        help="Message to encrypt/decrypt.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        configure_logging()
        config = HsmConfig.from_env()

        public_label = args.public_label or f"{args.private_label}.pub"
        with Pkcs11HsmClient(config) as client:
            private_key = client.get_private_key(args.private_label)
            public_key = client.get_public_key(public_label)
            if private_key is None or public_key is None:
                public_key, private_key = client.generate_rsa_keypair(
                    private_label=args.private_label,
                    public_label=public_label,
                    bits=3072,
                    extractable=False,
                    allow_sign=False,
                    allow_verify=False,
                    allow_encrypt=True,
                    allow_decrypt=True,
                )
                print(
                    f"Generated RSA confidentiality keypair: private={args.private_label} public={public_label}"
                )
            else:
                print(
                    f"Loaded existing RSA confidentiality keypair: private={args.private_label} public={public_label}"
                )

            ciphertext = client.encrypt_confidential(
                public_key,
                args.message.encode("utf-8"),
                algorithm=args.algorithm,
            )
            recovered = client.decrypt_confidential(
                private_key,
                ciphertext,
                algorithm=args.algorithm,
            ).decode("utf-8")

            print(f"Algorithm: {args.algorithm}")
            print(f"Ciphertext (base64): {base64.b64encode(ciphertext).decode('ascii')}")
            print(f"Recovered plaintext: {recovered}")
        return 0
    except (HsmClientError, ValueError) as exc:
        print(f"Client error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
