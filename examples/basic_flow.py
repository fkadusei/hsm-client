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
    from hsm_client import HsmConfig, HsmClientError, Pkcs11HsmClient
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
        description="Basic PKCS#11 flow: create or load AES key, encrypt, decrypt."
    )
    parser.add_argument(
        "--key-label",
        default="app-aes-key",
        help="Token label for the AES key (default: app-aes-key).",
    )
    parser.add_argument(
        "--message",
        default="hello from hsm client",
        help="Plaintext message to encrypt.",
    )
    parser.add_argument(
        "--aad",
        default=None,
        help="Optional additional authenticated data (used only when AES-GCM is available).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        config = HsmConfig.from_env()
        with Pkcs11HsmClient(config) as client:
            key = client.get_aes_key(args.key_label)
            if key is None:
                key = client.generate_aes_key(args.key_label, bits=256)
                print(f"Generated non-exportable AES-256 key: {args.key_label}")
            else:
                print(f"Loaded existing AES key: {args.key_label}")

            aad = args.aad.encode("utf-8") if args.aad is not None else None
            payload = client.encrypt_aes(
                key,
                args.message.encode("utf-8"),
                aad=aad,
                prefer_gcm=True,
            )
            recovered = client.decrypt_aes(key, payload).decode("utf-8")

            print(f"Mechanism used: {payload.mechanism}")
            label = "Nonce" if payload.mechanism == "AES_GCM" else "IV"
            print(f"{label} (base64): {base64.b64encode(payload.iv_or_nonce).decode('ascii')}")
            print(f"Ciphertext (base64): {base64.b64encode(payload.ciphertext).decode('ascii')}")
            if payload.mechanism == "AES_GCM":
                print(f"Tag bits: {payload.tag_bits}")
                if payload.aad is not None:
                    print(f"AAD (utf-8): {payload.aad.decode('utf-8', errors='replace')}")
            print(f"Recovered plaintext: {recovered}")
        return 0
    except HsmClientError as exc:
        print(f"HSM error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
