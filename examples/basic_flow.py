from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

try:
    from hsm_client import (
        AesCiphertext,
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

DEFAULT_KEY_LABEL = "app-aes-key"
ENVELOPE_VERSION = 1


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt or decrypt data using an HSM key. "
            "Encryption input can be --message, --file, or --object."
        )
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt plaintext input (default mode when no mode flag is provided).",
    )
    mode_group.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt from a payload envelope instead of encrypting plaintext.",
    )
    parser.add_argument(
        "--key-label",
        default=None,
        help=(
            "HSM key label to use. "
            "Encrypt default: app-aes-key. Decrypt default: key_label in payload envelope."
        ),
    )
    parser.add_argument(
        "--message",
        default=None,
        help="Plaintext message to encrypt.",
    )
    parser.add_argument(
        "--file",
        dest="file_path",
        default=None,
        help="Path to a file whose contents should be encrypted.",
    )
    parser.add_argument(
        "--object",
        dest="object_json",
        default=None,
        help="JSON object string to encrypt.",
    )
    parser.add_argument(
        "--aad",
        default=None,
        help="Optional additional authenticated data (used only when AES-GCM is available).",
    )
    parser.add_argument(
        "--payload",
        default=None,
        help="Encrypted payload JSON string (for --decrypt).",
    )
    parser.add_argument(
        "--payload-file",
        default=None,
        help="Path to encrypted payload JSON file (for --decrypt).",
    )
    parser.add_argument(
        "--out",
        default=None,
        help=(
            "Output path. Encrypt: write payload JSON. "
            "Decrypt: write plaintext output (required for binary file output)."
        ),
    )
    return parser.parse_args(argv)


def _decode_b64(name: str, value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64 for {name}.") from exc


def _validate_args(args: argparse.Namespace) -> None:
    if args.encrypt and args.decrypt:
        raise ValueError("Use only one mode flag: --encrypt or --decrypt.")

    has_message = args.message is not None
    has_file = args.file_path is not None
    has_object = args.object_json is not None
    source_count = int(has_message) + int(has_file) + int(has_object)

    if args.decrypt:
        if source_count > 0:
            raise ValueError("Do not provide --message, --file, or --object when using --decrypt.")
        if bool(args.payload) == bool(args.payload_file):
            raise ValueError("For --decrypt provide exactly one of --payload or --payload-file.")
        if args.aad is not None:
            raise ValueError("--aad is only valid for encryption.")
    else:
        if source_count != 1:
            raise ValueError("Provide exactly one encryption input: --message, --file, or --object.")
        if args.payload or args.payload_file:
            raise ValueError("--payload and --payload-file are only valid with --decrypt.")


def _load_plaintext_from_args(args: argparse.Namespace) -> tuple[str, bytes, dict[str, Any]]:
    if args.message is not None:
        return "message", args.message.encode("utf-8"), {"content_encoding": "utf-8"}

    if args.file_path is not None:
        path = Path(args.file_path)
        if not path.exists():
            raise ValueError(f"File does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"Path is not a file: {path}")
        return (
            "file",
            path.read_bytes(),
            {
                "content_encoding": "bytes",
                "filename": path.name,
            },
        )

    if args.object_json is not None:
        try:
            obj = json.loads(args.object_json)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--object must be valid JSON: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError("--object must be a JSON object (e.g. '{\"id\":123}').")
        canonical = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return "object", canonical, {"content_encoding": "json"}

    raise ValueError("No encryption input provided.")


def _build_envelope(
    *,
    key_label: str,
    source_type: str,
    source_meta: dict[str, Any],
    payload: AesCiphertext,
) -> dict[str, Any]:
    envelope: dict[str, Any] = {
        "version": ENVELOPE_VERSION,
        "key_label": key_label,
        "source_type": source_type,
        "mechanism": payload.mechanism,
        "iv_or_nonce_b64": base64.b64encode(payload.iv_or_nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(payload.ciphertext).decode("ascii"),
    }
    envelope.update(source_meta)
    if payload.aad is not None:
        envelope["aad_b64"] = base64.b64encode(payload.aad).decode("ascii")
    if payload.tag_bits is not None:
        envelope["tag_bits"] = payload.tag_bits
    return envelope


def _read_envelope(args: argparse.Namespace) -> dict[str, Any]:
    if args.payload is not None:
        raw = args.payload
    else:
        payload_path = Path(args.payload_file)
        if not payload_path.exists():
            raise ValueError(f"Payload file does not exist: {payload_path}")
        raw = payload_path.read_text(encoding="utf-8")

    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload is not valid JSON: {exc}") from exc

    if not isinstance(envelope, dict):
        raise ValueError("Payload JSON must be an object.")
    return envelope


def _payload_from_envelope(envelope: dict[str, Any]) -> AesCiphertext:
    required = ["mechanism", "iv_or_nonce_b64", "ciphertext_b64"]
    for field in required:
        if field not in envelope:
            raise ValueError(f"Payload JSON missing required field: {field}")

    aad = None
    aad_b64 = envelope.get("aad_b64")
    if aad_b64 is not None:
        if not isinstance(aad_b64, str):
            raise ValueError("aad_b64 must be a string when present.")
        aad = _decode_b64("aad_b64", aad_b64)

    mechanism = envelope["mechanism"]
    if not isinstance(mechanism, str):
        raise ValueError("mechanism must be a string.")

    tag_bits_raw = envelope.get("tag_bits")
    tag_bits = int(tag_bits_raw) if tag_bits_raw is not None else None

    return AesCiphertext(
        mechanism=mechanism,
        iv_or_nonce=_decode_b64("iv_or_nonce_b64", str(envelope["iv_or_nonce_b64"])),
        ciphertext=_decode_b64("ciphertext_b64", str(envelope["ciphertext_b64"])),
        aad=aad,
        tag_bits=tag_bits,
    )


def _write_or_print_json(data: dict[str, Any], out_path: str | None) -> None:
    rendered = json.dumps(data, indent=2, sort_keys=True)
    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote payload envelope to: {path}")
    else:
        print(rendered)


def _write_decrypted_output(
    *,
    source_type: str,
    plaintext: bytes,
    out_path: str | None,
) -> None:
    if source_type == "file":
        if out_path:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(plaintext)
            print(f"Wrote decrypted file to: {path}")
            return

        print(base64.b64encode(plaintext).decode("ascii"))
        print("Note: output is base64 because source_type=file. Use --out to write raw bytes.")
        return

    if source_type == "object":
        text = plaintext.decode("utf-8")
        obj = json.loads(text)
        rendered = json.dumps(obj, indent=2, sort_keys=True)
        if out_path:
            path = Path(out_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rendered + "\n", encoding="utf-8")
            print(f"Wrote decrypted object to: {path}")
        else:
            print(rendered)
        return

    text = plaintext.decode("utf-8")
    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"Wrote decrypted message to: {path}")
    else:
        print(text)


def _run_encrypt(args: argparse.Namespace, client: Pkcs11HsmClient) -> int:
    key_label = args.key_label or DEFAULT_KEY_LABEL
    key = client.get_aes_key(key_label)
    if key is None:
        key = client.generate_aes_key(key_label, bits=256)
        print(f"Generated non-exportable AES-256 key: {key_label}")
    else:
        print(f"Loaded existing AES key: {key_label}")

    source_type, plaintext, source_meta = _load_plaintext_from_args(args)
    aad = args.aad.encode("utf-8") if args.aad is not None else None
    encrypted = client.encrypt_aes(key, plaintext, aad=aad, prefer_gcm=True)

    envelope = _build_envelope(
        key_label=key_label,
        source_type=source_type,
        source_meta=source_meta,
        payload=encrypted,
    )

    print(f"Mechanism used: {encrypted.mechanism}")
    _write_or_print_json(envelope, args.out)
    return 0


def _run_decrypt(args: argparse.Namespace, client: Pkcs11HsmClient) -> int:
    envelope = _read_envelope(args)
    payload = _payload_from_envelope(envelope)

    envelope_key_label = envelope.get("key_label")
    if envelope_key_label is not None and not isinstance(envelope_key_label, str):
        raise ValueError("Payload key_label must be a string when present.")

    key_label = args.key_label or envelope_key_label
    if not key_label:
        raise ValueError("Could not determine key label. Provide --key-label or payload key_label.")

    key = client.get_aes_key(key_label)
    if key is None:
        raise ValueError(f"No AES key found for label: {key_label}")

    plaintext = client.decrypt_aes(key, payload)
    source_type = envelope.get("source_type", "message")
    if not isinstance(source_type, str):
        raise ValueError("Payload source_type must be a string when present.")

    print(f"Decryption mechanism: {payload.mechanism}")
    print(f"Source type: {source_type}")
    _write_decrypted_output(source_type=source_type, plaintext=plaintext, out_path=args.out)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        _validate_args(args)
        configure_logging()
        config = HsmConfig.from_env()

        with Pkcs11HsmClient(config) as client:
            if args.decrypt:
                return _run_decrypt(args, client)
            return _run_encrypt(args, client)
    except (HsmClientError, ValueError, OSError, UnicodeError) as exc:
        print(f"Client error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
