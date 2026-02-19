from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

if __package__ in (None, ""):
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

try:
    from hsm_client import (
        DetachedSignature,
        HsmClientError,
        HsmConfig,
        Pkcs11HsmClient,
        configure_logging,
        list_key_profiles,
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


class _HelpFormatter(
    argparse.RawTextHelpFormatter,
    argparse.ArgumentDefaultsHelpFormatter,
):
    """Keep multiline examples readable and include defaults."""


CLI_HELP_EPILOG = """Environment:
  Required:
    HSM_PKCS11_MODULE
    HSM_USER_PIN
    HSM_TOKEN_LABEL or HSM_SLOT

  Optional policy controls:
    HSM_ALLOW_ROOT_CA=true    # required for root CA operations
    HSM_OPERATION_ROLE=any    # any | ca | app

Examples:
  # Unified entrypoint for symmetric
  python3 examples/hsm_cli.py --mode symmetric --message "hello symmetric" --out payload.json
  python3 examples/hsm_cli.py --mode symmetric --decrypt --payload-file payload.json

  # Generate root CA keypair and root certificate
  python3 examples/hsm_cli.py --mode pki keygen --profile ca_root --private-label root-ca-key --ceremony-reference CEREMONY-2026Q1
  python3 examples/hsm_cli.py --mode pki cert sign --cert-type root --issuer-private-label root-ca-key --subject-cn "Example Root CA" --ceremony-reference CEREMONY-2026Q1 --out root-ca.pem

  # Issue intermediate certificate
  python3 examples/hsm_cli.py --mode pki keygen --profile ca_intermediate --private-label intermediate-ca-key
  python3 examples/hsm_cli.py --mode pki csr create --private-label intermediate-ca-key --subject-cn "Example Intermediate CA" --is-ca --out intermediate.csr.pem
  python3 examples/hsm_cli.py --mode pki cert sign --cert-type intermediate --issuer-private-label root-ca-key --issuer-cert-file root-ca.pem --csr-file intermediate.csr.pem --ceremony-reference CEREMONY-2026Q1 --out intermediate.pem

  # Detached signature for a message
  python3 examples/hsm_cli.py --mode pki sign --private-label app-signing-key --message "payload to sign" --out detached-signature.json
  python3 examples/hsm_cli.py --mode pki verify --public-label app-signing-key.pub --signature-file detached-signature.json --message "payload to sign"
"""


def _write_text_output(payload: str, out_path: str | None, label: str) -> None:
    if out_path is None:
        print(payload)
        return
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")
    print(f"Wrote {label} to: {target}")


def _write_json_output(payload: dict[str, object], out_path: str | None, label: str) -> None:
    _write_text_output(json.dumps(payload, indent=2, sort_keys=True), out_path, label)


def _write_pem_output(payload: bytes, out_path: str | None, label: str) -> None:
    _write_text_output(payload.decode("utf-8"), out_path=out_path, label=label)


def _read_text_input(
    *,
    inline_value: str | None,
    file_path: str | None,
    value_name: str,
) -> str:
    if bool(inline_value) == bool(file_path):
        raise ValueError(f"Provide exactly one of --{value_name} or --{value_name}-file.")
    if inline_value is not None:
        return inline_value

    path = Path(file_path)
    if not path.exists():
        raise ValueError(f"File does not exist: {path}")
    if not path.is_file():
        raise ValueError(f"Path is not a file: {path}")
    return path.read_text(encoding="utf-8")


def _read_binary_file(path: str) -> bytes:
    source = Path(path)
    if not source.exists():
        raise ValueError(f"File does not exist: {source}")
    if not source.is_file():
        raise ValueError(f"Path is not a file: {source}")
    return source.read_bytes()


def _add_subject_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--subject-cn",
        required=True,
        help="Subject common name (CN).",
    )
    parser.add_argument("--org", default=None, help="Subject organization (O).")
    parser.add_argument(
        "--ou",
        default=None,
        help="Subject organizational unit (OU).",
    )
    parser.add_argument(
        "--country",
        default=None,
        help="Subject country code (C), for example US.",
    )
    parser.add_argument(
        "--state",
        default=None,
        help="Subject state/province (ST).",
    )
    parser.add_argument(
        "--locality",
        default=None,
        help="Subject locality/city (L).",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "PKI CLI for key generation, CSR/certificate workflows, "
            "and detached signature operations backed by PKCS#11 HSM keys."
        ),
        formatter_class=_HelpFormatter,
        epilog=CLI_HELP_EPILOG,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    keygen = subparsers.add_parser(
        "keygen",
        help="Generate asymmetric keys by profile or explicit type.",
        formatter_class=_HelpFormatter,
    )
    keygen.add_argument("--private-label", required=True, help="Private key label.")
    keygen.add_argument(
        "--public-label",
        default=None,
        help="Public key label (default: <private-label>.pub).",
    )
    keygen.add_argument(
        "--profile",
        choices=list_key_profiles(),
        default=None,
        help="Optional predefined key profile.",
    )
    keygen.add_argument(
        "--type",
        choices=["rsa", "ec"],
        default=None,
        help="Key type when --profile is not used.",
    )
    keygen.add_argument(
        "--bits",
        type=int,
        default=3072,
        help="RSA key size when --type rsa (default: 3072).",
    )
    keygen.add_argument(
        "--curve",
        default="secp256r1",
        help="EC curve when --type ec (default: secp256r1).",
    )
    keygen.add_argument(
        "--ceremony-reference",
        default=None,
        help="Required for root CA profile operations.",
    )

    csr_cmd = subparsers.add_parser(
        "csr",
        help="CSR operations.",
        formatter_class=_HelpFormatter,
    )
    csr_sub = csr_cmd.add_subparsers(dest="csr_command", required=True)
    csr_create = csr_sub.add_parser(
        "create",
        help="Create a CSR.",
        formatter_class=_HelpFormatter,
    )
    csr_create.add_argument("--private-label", required=True, help="Private key label.")
    csr_create.add_argument(
        "--public-label",
        default=None,
        help="Public key label (default: <private-label>.pub).",
    )
    _add_subject_args(csr_create)
    csr_create.add_argument(
        "--signing-algorithm",
        default=None,
        help="Optional signing algorithm override.",
    )
    csr_create.add_argument(
        "--is-ca",
        action="store_true",
        help="Include CA requested extensions in CSR.",
    )
    csr_create.add_argument(
        "--ca-path-length",
        type=int,
        default=None,
        help="Requested CA pathLen when --is-ca is set.",
    )
    csr_create.add_argument(
        "--leaf-usage",
        choices=["server", "client", "both"],
        default=None,
        help="Leaf usage metadata for non-CA CSR.",
    )
    csr_create.add_argument(
        "--dns",
        action="append",
        default=None,
        help="DNS SAN entry for non-CA CSR. Repeatable.",
    )
    csr_create.add_argument(
        "--out",
        default=None,
        help="Output path for CSR PEM (default: stdout).",
    )

    cert_cmd = subparsers.add_parser(
        "cert",
        help="Certificate issuance operations.",
        formatter_class=_HelpFormatter,
    )
    cert_sub = cert_cmd.add_subparsers(dest="cert_command", required=True)
    cert_sign = cert_sub.add_parser(
        "sign",
        help="Sign a CSR into a certificate.",
        formatter_class=_HelpFormatter,
    )
    cert_sign.add_argument(
        "--cert-type",
        required=True,
        choices=["root", "intermediate", "leaf-server", "leaf-client", "leaf-both"],
        help="Certificate type to issue.",
    )
    cert_sign.add_argument(
        "--issuer-private-label",
        required=True,
        help="Issuer private key label in HSM.",
    )
    cert_sign.add_argument(
        "--issuer-public-label",
        default=None,
        help="Optional issuer public key label for algorithm defaulting.",
    )
    cert_sign.add_argument("--issuer-cert", default=None, help="Issuer cert PEM content.")
    cert_sign.add_argument(
        "--issuer-cert-file",
        default=None,
        help="Path to issuer cert PEM file.",
    )
    cert_sign.add_argument("--csr", default=None, help="CSR PEM content.")
    cert_sign.add_argument(
        "--csr-file",
        default=None,
        help="Path to CSR PEM file.",
    )
    cert_sign.add_argument(
        "--signing-algorithm",
        default=None,
        help="Optional signing algorithm override.",
    )
    cert_sign.add_argument(
        "--validity-days",
        type=int,
        default=None,
        help="Certificate validity in days.",
    )
    cert_sign.add_argument(
        "--ca-path-length",
        type=int,
        default=None,
        help="CA pathLen constraint (root default: 1, intermediate default: 0).",
    )
    cert_sign.add_argument("--subject-cn", default=None, help="Subject CN for root cert.")
    cert_sign.add_argument("--org", default=None, help="Subject organization for root cert.")
    cert_sign.add_argument("--ou", default=None, help="Subject OU for root cert.")
    cert_sign.add_argument("--country", default=None, help="Subject country for root cert.")
    cert_sign.add_argument("--state", default=None, help="Subject state for root cert.")
    cert_sign.add_argument("--locality", default=None, help="Subject locality for root cert.")
    cert_sign.add_argument(
        "--ceremony-reference",
        default=None,
        help="Required when cert-type is root or intermediate.",
    )
    cert_sign.add_argument(
        "--dns",
        action="append",
        default=None,
        help="DNS SAN override for leaf certificates. Repeatable.",
    )
    cert_sign.add_argument(
        "--leaf-private-label",
        default=None,
        help="Leaf private key label for chain metadata return.",
    )
    cert_sign.add_argument(
        "--leaf-public-label",
        default=None,
        help="Leaf public key label (default: <leaf-private-label>.pub).",
    )
    cert_sign.add_argument(
        "--root-cert-file",
        default=None,
        help="Optional root cert PEM file to include full chain output for leaf issuance.",
    )
    cert_sign.add_argument(
        "--out",
        default=None,
        help="Output path for issued certificate PEM (default: stdout).",
    )
    cert_sign.add_argument(
        "--chain-out",
        default=None,
        help="Output path for certificate chain PEM (leaf issuance only).",
    )

    sign_cmd = subparsers.add_parser(
        "sign",
        help="Create a detached signature for blob data or a precomputed digest.",
        formatter_class=_HelpFormatter,
    )
    sign_cmd.add_argument("--private-label", required=True, help="Signing private key label.")
    sign_cmd.add_argument(
        "--algorithm",
        default="rsa_pss_sha256",
        help="Signing algorithm (default: rsa_pss_sha256).",
    )
    sign_input = sign_cmd.add_mutually_exclusive_group(required=True)
    sign_input.add_argument("--message", default=None, help="Message text to sign.")
    sign_input.add_argument("--file", dest="file_path", default=None, help="File to sign.")
    sign_input.add_argument(
        "--digest-hex",
        default=None,
        help="Precomputed digest hex string for digest-level signing.",
    )
    sign_cmd.add_argument(
        "--out",
        default=None,
        help="Output path for detached signature JSON (default: stdout).",
    )

    verify_cmd = subparsers.add_parser(
        "verify",
        help="Verify a detached signature against blob data or digest.",
        formatter_class=_HelpFormatter,
    )
    verify_cmd.add_argument("--public-label", required=True, help="Verification public key label.")
    verify_cmd.add_argument(
        "--signature-json",
        default=None,
        help="Detached signature JSON payload.",
    )
    verify_cmd.add_argument(
        "--signature-file",
        default=None,
        help="Detached signature JSON file path.",
    )
    verify_input = verify_cmd.add_mutually_exclusive_group(required=True)
    verify_input.add_argument("--message", default=None, help="Message text to verify.")
    verify_input.add_argument("--file", dest="file_path", default=None, help="File to verify.")
    verify_input.add_argument(
        "--digest-hex",
        default=None,
        help="Precomputed digest hex string for digest-level verification.",
    )

    rotation_cmd = subparsers.add_parser(
        "rotation",
        help="Rotation plan scaffolding.",
        formatter_class=_HelpFormatter,
    )
    rotation_sub = rotation_cmd.add_subparsers(dest="rotation_command", required=True)
    rotation_plan = rotation_sub.add_parser(
        "plan",
        help="Render profile rotation plan.",
        formatter_class=_HelpFormatter,
    )
    rotation_plan.add_argument(
        "--profile",
        required=True,
        choices=list_key_profiles(),
        help="Profile name.",
    )
    rotation_plan.add_argument("--base-label", required=True, help="Versioned key base label.")
    rotation_plan.add_argument(
        "--current-version",
        type=int,
        default=None,
        help="Current active key version.",
    )
    rotation_plan.add_argument(
        "--from-token",
        action="store_true",
        help="Discover current version from token object labels.",
    )
    rotation_plan.add_argument(
        "--out",
        default=None,
        help="Output path for rotation plan JSON (default: stdout).",
    )

    return parser


def _resolve_blob_from_args(args: argparse.Namespace) -> bytes:
    if args.message is not None:
        return args.message.encode("utf-8")
    if args.file_path is not None:
        return _read_binary_file(args.file_path)
    raise ValueError("Blob input requires --message or --file.")


def _resolve_digest_hex(value: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError("Invalid hex provided for --digest-hex.") from exc


def _run_keygen(args: argparse.Namespace) -> None:
    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        if args.profile:
            if args.profile == "ca_root":
                if not args.ceremony_reference:
                    raise ValueError("--ceremony-reference is required for profile ca_root.")
                client.create_root_ca_key(
                    private_label=args.private_label,
                    public_label=args.public_label,
                    ceremony_reference=args.ceremony_reference,
                )
            elif args.profile == "ca_intermediate":
                client.create_intermediate_key(
                    private_label=args.private_label,
                    public_label=args.public_label,
                )
            else:
                client.generate_keypair_for_profile(
                    args.profile,
                    private_label=args.private_label,
                    public_label=args.public_label,
                )
            key_type = client.get_key_profile(args.profile).key_type.lower()
            profile_name = args.profile
        else:
            if args.type is None:
                raise ValueError("Use --profile or provide --type rsa|ec.")
            if args.type == "rsa":
                client.generate_rsa_keypair(
                    private_label=args.private_label,
                    public_label=args.public_label,
                    bits=args.bits,
                    extractable=False,
                )
                key_type = "rsa"
            else:
                client.generate_ec_keypair(
                    private_label=args.private_label,
                    public_label=args.public_label,
                    curve=args.curve,
                    extractable=False,
                )
                key_type = "ec"
            profile_name = None

    payload: dict[str, object] = {
        "operation": "keygen",
        "private_label": args.private_label,
        "public_label": args.public_label or f"{args.private_label}.pub",
        "key_type": key_type,
    }
    if profile_name is not None:
        payload["profile"] = profile_name
    _write_json_output(payload, out_path=None, label="key metadata")


def _run_csr_create(args: argparse.Namespace) -> None:
    if args.ca_path_length is not None and not args.is_ca:
        raise ValueError("--ca-path-length requires --is-ca.")
    if args.is_ca and args.leaf_usage is not None:
        raise ValueError("--leaf-usage is not valid with --is-ca.")
    if args.is_ca and args.dns:
        raise ValueError("--dns is not valid with --is-ca.")

    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        csr_pem = client.create_csr(
            private_label=args.private_label,
            public_label=args.public_label,
            subject_common_name=args.subject_cn,
            organization=args.org,
            organizational_unit=args.ou,
            country=args.country,
            state_or_province=args.state,
            locality=args.locality,
            signing_algorithm=args.signing_algorithm,
            is_ca=args.is_ca,
            ca_path_length=args.ca_path_length,
            mtls_usage=args.leaf_usage,
            dns_names=args.dns,
        )
    _write_pem_output(csr_pem, out_path=args.out, label="certificate signing request")


def _run_cert_sign(args: argparse.Namespace) -> None:
    validity_days = args.validity_days
    if validity_days is None:
        if args.cert_type == "root":
            validity_days = 3650
        elif args.cert_type == "intermediate":
            validity_days = 1825
        else:
            validity_days = 397

    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        if args.cert_type == "root":
            if not args.ceremony_reference:
                raise ValueError("--ceremony-reference is required when cert-type=root.")
            if not args.subject_cn:
                raise ValueError("--subject-cn is required when cert-type=root.")
            root_path_length = args.ca_path_length if args.ca_path_length is not None else 1
            cert_pem = client.create_root_ca_cert(
                root_private_label=args.issuer_private_label,
                root_public_label=args.issuer_public_label,
                subject_common_name=args.subject_cn,
                organization=args.org,
                organizational_unit=args.ou,
                country=args.country,
                state_or_province=args.state,
                locality=args.locality,
                signing_algorithm=args.signing_algorithm,
                validity_days=validity_days,
                path_length=root_path_length,
                ceremony_reference=args.ceremony_reference,
            )
            _write_pem_output(cert_pem, out_path=args.out, label="root certificate")
            return

        issuer_cert_pem = _read_text_input(
            inline_value=args.issuer_cert,
            file_path=args.issuer_cert_file,
            value_name="issuer-cert",
        )
        csr_pem = _read_text_input(
            inline_value=args.csr,
            file_path=args.csr_file,
            value_name="csr",
        )

        if args.cert_type == "intermediate":
            if not args.ceremony_reference:
                raise ValueError(
                    "--ceremony-reference is required when cert-type=intermediate."
                )
            intermediate_path_length = (
                args.ca_path_length if args.ca_path_length is not None else 0
            )
            cert_pem = client.sign_intermediate_csr(
                root_private_label=args.issuer_private_label,
                root_certificate_pem=issuer_cert_pem,
                intermediate_csr_pem=csr_pem,
                root_public_label=args.issuer_public_label,
                signing_algorithm=args.signing_algorithm,
                validity_days=validity_days,
                path_length=intermediate_path_length,
                ceremony_reference=args.ceremony_reference,
            )
            _write_pem_output(cert_pem, out_path=args.out, label="intermediate certificate")
            return

        usage_map = {
            "leaf-server": "server",
            "leaf-client": "client",
            "leaf-both": "both",
        }
        usage = usage_map[args.cert_type]
        if args.leaf_private_label:
            root_cert_pem = None
            if args.root_cert_file:
                root_cert_pem = Path(args.root_cert_file).read_text(encoding="utf-8")
            issued = client.sign_mtls_leaf_csr(
                profile_name="mtls_client" if usage == "client" else "mtls_server",
                leaf_private_label=args.leaf_private_label,
                leaf_public_label=args.leaf_public_label,
                leaf_csr_pem=csr_pem,
                intermediate_private_label=args.issuer_private_label,
                intermediate_public_label=args.issuer_public_label,
                intermediate_certificate_pem=issuer_cert_pem,
                root_certificate_pem=root_cert_pem,
                signing_algorithm=args.signing_algorithm,
                validity_days=validity_days,
                mtls_usage=usage,
                dns_names=args.dns,
            )
            _write_pem_output(issued.certificate_pem, out_path=args.out, label="leaf certificate")
            if args.chain_out:
                _write_pem_output(
                    issued.certificate_chain_pem,
                    out_path=args.chain_out,
                    label="certificate chain",
                )
            _write_json_output(
                {
                    "operation": "cert-sign-leaf",
                    "profile": issued.profile_name,
                    "private_key_label": issued.private_key_label,
                    "public_key_label": issued.public_key_label,
                },
                out_path=None,
                label="leaf issuance metadata",
            )
            return

        cert_pem = client.sign_leaf_csr(
            intermediate_private_label=args.issuer_private_label,
            intermediate_public_label=args.issuer_public_label,
            intermediate_certificate_pem=issuer_cert_pem,
            leaf_csr_pem=csr_pem,
            signing_algorithm=args.signing_algorithm,
            validity_days=validity_days,
            mtls_usage=usage,
            dns_names=args.dns,
        )
        _write_pem_output(cert_pem, out_path=args.out, label="leaf certificate")


def _run_sign(args: argparse.Namespace) -> None:
    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        if args.digest_hex is not None:
            signature = client.sign_digest(
                private_label=args.private_label,
                digest=_resolve_digest_hex(args.digest_hex),
                algorithm=args.algorithm,
            )
        else:
            signature = client.sign_blob(
                private_label=args.private_label,
                blob=_resolve_blob_from_args(args),
                algorithm=args.algorithm,
            )
    _write_json_output(signature.to_dict(), out_path=args.out, label="detached signature")


def _run_verify(args: argparse.Namespace) -> int:
    if bool(args.signature_json) == bool(args.signature_file):
        raise ValueError("Provide exactly one of --signature-json or --signature-file.")
    if args.signature_json is not None:
        signature_payload = args.signature_json
    else:
        signature_path = Path(args.signature_file)
        if not signature_path.exists():
            raise ValueError(f"File does not exist: {signature_path}")
        if not signature_path.is_file():
            raise ValueError(f"Path is not a file: {signature_path}")
        signature_payload = signature_path.read_text(encoding="utf-8")
    detached = DetachedSignature.from_json(signature_payload)

    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        if detached.input_type == "digest":
            if args.digest_hex is None:
                raise ValueError(
                    "Detached signature expects digest input. Provide --digest-hex."
                )
            verified = client.verify_digest(
                public_label=args.public_label,
                digest=_resolve_digest_hex(args.digest_hex),
                detached_signature=detached,
            )
        elif detached.input_type == "blob":
            if args.digest_hex is not None:
                raise ValueError(
                    "Detached signature expects blob input. Use --message or --file."
                )
            verified = client.verify_blob(
                public_label=args.public_label,
                blob=_resolve_blob_from_args(args),
                detached_signature=detached,
            )
        else:
            raise ValueError(
                f"Unsupported detached signature input_type: {detached.input_type}"
            )

    _write_json_output(
        {
            "operation": "verify",
            "verified": verified,
            "algorithm": detached.algorithm,
            "hash_algorithm": detached.hash_algorithm,
            "input_type": detached.input_type,
        },
        out_path=None,
        label="verification result",
    )
    return 0 if verified else 1


def _run_rotation_plan(args: argparse.Namespace) -> None:
    config = HsmConfig.from_env()
    with Pkcs11HsmClient(config) as client:
        if args.from_token:
            plan = client.build_profile_rotation_plan_from_token(
                profile_name=args.profile,
                base_label=args.base_label,
            )
        else:
            plan = client.build_profile_rotation_plan(
                profile_name=args.profile,
                base_label=args.base_label,
                current_version=args.current_version,
            )
    _write_json_output(asdict(plan), out_path=args.out, label="rotation plan")


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        configure_logging()

        if args.command == "keygen":
            _run_keygen(args)
            return 0

        if args.command == "csr" and args.csr_command == "create":
            _run_csr_create(args)
            return 0

        if args.command == "cert" and args.cert_command == "sign":
            _run_cert_sign(args)
            return 0

        if args.command == "sign":
            _run_sign(args)
            return 0

        if args.command == "verify":
            return _run_verify(args)

        if args.command == "rotation" and args.rotation_command == "plan":
            _run_rotation_plan(args)
            return 0

        raise ValueError("Unsupported command combination.")
    except (HsmClientError, ValueError) as exc:
        print(f"PKI CLI error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
