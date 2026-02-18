from __future__ import annotations

import argparse
import base64
import sys
import uuid
from pathlib import Path

if __package__ in (None, ""):
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

try:
    from hsm_client import HsmConfig, HsmClientError, Pkcs11HsmClient, configure_logging
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
            "Lifecycle demo: rotate versioned AES keys, create KEK, "
            "wrap/unwrap a transfer key."
        )
    )
    parser.add_argument(
        "--base-label",
        default="app-main-key",
        help="Base key label for rotation (default: app-main-key).",
    )
    parser.add_argument(
        "--message",
        default="lifecycle demo payload",
        help="Message to encrypt/decrypt with rotated key.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        configure_logging()
        config = HsmConfig.from_env()
        with Pkcs11HsmClient(config) as client:
            # 1) Rotate key versions.
            created_version, _created_key = client.rotate_aes_key(args.base_label, bits=256)
            latest = client.get_latest_aes_key(args.base_label)
            if latest is None:
                raise RuntimeError("Expected latest versioned key after rotation.")
            latest_version, latest_key = latest

            print(f"Created versioned key: {created_version.label}")
            print(f"Latest versioned key: {latest_version.label}")

            payload = client.encrypt_aes(latest_key, args.message.encode("utf-8"), prefer_gcm=True)
            recovered = client.decrypt_aes(latest_key, payload).decode("utf-8")
            print(f"Latest key mechanism: {payload.mechanism}")
            print(f"Recovered plaintext: {recovered}")

            # 2) Wrap and unwrap flow.
            kek_label = f"{args.base_label}-kek"
            kek = client.get_aes_key(kek_label)
            if kek is None:
                kek = client.generate_aes_kek(kek_label, bits=256)
                print(f"Generated KEK: {kek_label}")
            else:
                print(f"Loaded KEK: {kek_label}")

            transfer_source_label = f"{args.base_label}-transfer-src-{uuid.uuid4().hex[:6]}"
            transfer_destination_label = f"{args.base_label}-transfer-dst-{uuid.uuid4().hex[:6]}"
            transfer_source = client.generate_aes_key(
                transfer_source_label,
                bits=256,
                extractable=True,
            )
            wrapped = client.wrap_aes_key(kek, transfer_source)
            transfer_destination = client.unwrap_aes_key(
                kek,
                wrapped,
                label=transfer_destination_label,
            )
            wrapped_b64 = base64.b64encode(wrapped).decode("ascii")

            print(f"Wrapped key bytes (base64): {wrapped_b64}")
            print(f"Unwrapped key label: {transfer_destination_label}")

            transfer_payload = client.encrypt_aes(
                transfer_destination,
                b"transfer-check",
                prefer_gcm=True,
            )
            transfer_plaintext = client.decrypt_aes(
                transfer_destination,
                transfer_payload,
            ).decode("utf-8")
            print(f"Transfer key round-trip: {transfer_plaintext}")

        return 0
    except (HsmClientError, ValueError) as exc:
        print(f"Client error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
