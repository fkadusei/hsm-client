# hsm-client

Minimal Python starter for connecting to an HSM over `PKCS#11` and performing symmetric cryptography without exporting key bytes.

## What this starter does

- Loads PKCS#11 module and opens an authenticated session.
- Finds an AES key by label or creates one if missing.
- Encrypts and decrypts data using key handles in the HSM.
- Prefers AES-GCM and falls back to AES-CBC-PAD when GCM is unavailable.
- Enforces non-exportable keys by default (`CKA_EXTRACTABLE=false`).
- Supports key lifecycle workflows: versioned rotation and key wrap/unwrap.
- Supports asymmetric key operations for CA, mTLS, and digital signing profiles.
- Supports asymmetric confidentiality flow (public-key encrypt, private-key decrypt).
- Supports X.509 CSR and CA certificate workflows with HSM-backed signing keys.

## Prerequisites

- Python 3.10+
- Access to a PKCS#11-compatible HSM or simulator
- Vendor PKCS#11 shared library path (for example: `/opt/vendor/lib/libCryptoki2.so`)
- A token/partition configured with user PIN

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Configure environment

Use either token label or slot number.

```bash
export HSM_PKCS11_MODULE="/path/to/pkcs11/library.so"
export HSM_TOKEN_LABEL="my-app-token"   # optional if HSM_SLOT is set
export HSM_SLOT="0"                      # optional if HSM_TOKEN_LABEL is set
export HSM_USER_PIN="1234"
```

Optional:

```bash
export HSM_USER_PIN_ENV="MY_CUSTOM_PIN_VAR"
export MY_CUSTOM_PIN_VAR="1234"
```

For root CA ceremonies, explicitly enable root operations:

```bash
export HSM_ALLOW_ROOT_CA="true"
```

Optional role separation control:

```bash
export HSM_OPERATION_ROLE="any"  # any | ca | app
```

## Logging

Both example scripts configure rotating file logging automatically.

- Default log file: `logs/hsm-client.log`
- Rotation policy: 5 backups, 5MB each

Optional logging environment overrides:

```bash
export HSM_CLIENT_LOG_FILE="logs/hsm-client.log"
export HSM_CLIENT_LOG_LEVEL="INFO"        # DEBUG, INFO, WARNING, ERROR
export HSM_CLIENT_LOG_MAX_BYTES="5242880" # 5MB
export HSM_CLIENT_LOG_BACKUP_COUNT="5"
```

## Unified CLI Entry Point

Use a single file for both symmetric and PKI workflows:

```bash
python3 examples/hsm_cli.py --mode symmetric ...
python3 examples/hsm_cli.py --mode pki ...
```

Mode-specific help from the same file:

```bash
python3 examples/hsm_cli.py --mode symmetric --help
python3 examples/hsm_cli.py --mode pki --help
```

Mode options:

- `--mode symmetric`: AES encrypt/decrypt quick tests (basic flow behavior)
- `--mode pki`: keygen, CSR/cert issuance, detached signing/verification, rotation planning

## Basic Flow CLI

Use `examples/hsm_cli.py --mode symmetric` with these modes:

- Encrypt mode (default, or explicit `--encrypt`): requires exactly one of `--message`, `--file`, or `--object`
- Decrypt mode (`--decrypt`): requires exactly one of `--payload` or `--payload-file`

Output behavior:

- Encrypt mode: emits a JSON payload envelope to stdout, or writes it with `--out`
- Decrypt mode:
  - `message` source type: prints plaintext, or writes text with `--out`
  - `object` source type: prints formatted JSON, or writes JSON with `--out`
  - `file` source type: prints base64 by default, or writes raw bytes with `--out`

Key label behavior:

- Encrypt: defaults to `app-aes-key` if `--key-label` is not set
- Decrypt: uses `--key-label` if provided, otherwise uses `key_label` from the payload envelope

### Encryption Examples

Encrypt a quick message:

```bash
python3 examples/hsm_cli.py --mode symmetric --encrypt --message "test payload" --out payload.json
```

Encrypt a file:

```bash
python3 examples/hsm_cli.py --mode symmetric --file ./document.pdf --out document.payload.json
```

Encrypt a JSON object:

```bash
python3 examples/hsm_cli.py --mode symmetric --object '{"user_id":123,"role":"admin"}' --out object.payload.json
```

Optional AAD for encryption (used only when AES-GCM is selected):

```bash
python3 examples/hsm_cli.py --mode symmetric --message "test payload" --aad "request-id=abc123" --out payload.json
```

### Decryption Examples

Decrypt from payload file:

```bash
python3 examples/hsm_cli.py --mode symmetric --decrypt --payload-file payload.json
```

Decrypt from inline payload JSON string:

```bash
python3 examples/hsm_cli.py --mode symmetric --decrypt --payload '{"key_label":"app-aes-key","mechanism":"AES_GCM","iv_or_nonce_b64":"...","ciphertext_b64":"..."}'
```

Decrypt a file payload back to bytes:

```bash
python3 examples/hsm_cli.py --mode symmetric --decrypt --payload-file document.payload.json --out ./document.decrypted.pdf
```

Decrypt an object payload:

```bash
python3 examples/hsm_cli.py --mode symmetric --decrypt --payload-file object.payload.json
```

Note: if your HSM does not support AES-GCM, the client falls back to AES-CBC-PAD only when no AAD is provided.

## Key lifecycle example (rotation + wrap/unwrap)

```bash
python3 examples/key_lifecycle.py --base-label app-main-key --message "rotation payload"
```

What it demonstrates:

- Rotates keys using versioned labels (`<base>-v0001`, `<base>-v0002`, ...).
- Loads the latest version and performs encrypt/decrypt.
- Generates a KEK and wraps/unwraps a transfer key.

Important: many PKCS#11 providers require wrapped keys to be extractable at wrap time. Keep production application keys non-extractable unless you intentionally support wrapped export workflows.

## Asymmetric key operations (Phase 1-3)

The client now includes:

- key profiles: `ca_root`, `ca_intermediate`, `mtls_server`, `mtls_client`, `signing`
- keypair generation:
  - `generate_rsa_keypair(...)`
  - `generate_ec_keypair(...)`
  - `generate_keypair_for_profile(...)`
- key retrieval:
  - `get_private_key(...)`
  - `get_public_key(...)`
- signing/verification with explicit mechanism mapping:
  - `rsa_pkcs1v15_sha256`, `rsa_pkcs1v15_sha384`
  - `rsa_pss_sha256`, `rsa_pss_sha384`
  - `ecdsa_sha256`, `ecdsa_sha384`
- confidentiality encryption/decryption with explicit mechanism mapping:
  - `rsa_oaep_sha1`, `rsa_oaep_sha256`, `rsa_oaep_sha384`
  - `rsa_pkcs1v15`

Python usage example:

```python
from hsm_client import HsmConfig, Pkcs11HsmClient

config = HsmConfig.from_env()
with Pkcs11HsmClient(config) as client:
    public_key, private_key = client.generate_keypair_for_profile(
        "mtls_server",
        private_label="mtls-server-key",
    )
    message = b"hello-signature"
    signature = client.sign(private_key, message, algorithm="ecdsa_sha256")
    assert client.verify(public_key, message, signature, algorithm="ecdsa_sha256")
```

## CA workflows (root + intermediate)

New APIs:

- `create_root_ca_key(...)`
- `create_root_ca_cert(...)`
- `create_intermediate_key(...)`
- `create_csr(...)`
- `sign_intermediate_csr(...)`
- `sign_leaf_csr(...)`
- `generate_mtls_leaf_key_and_csr(...)`
- `sign_mtls_leaf_csr(...)`
- `sign_blob(...)` / `verify_blob(...)`
- `sign_digest(...)` / `verify_digest(...)`

Root operations are policy-gated and require:

- `HSM_ALLOW_ROOT_CA=true`
- a non-empty `ceremony_reference` argument

Role separation policy:

- Set `HSM_OPERATION_ROLE=ca` for CA operations (certificate issuance, CA key ops).
- Set `HSM_OPERATION_ROLE=app` for application signing operations.
- Use `HSM_OPERATION_ROLE=any` to disable role enforcement in development.

Python usage example:

```python
from hsm_client import HsmConfig, Pkcs11HsmClient

config = HsmConfig.from_env()
ceremony = "2026-q1-root-ca-ceremony"

with Pkcs11HsmClient(config) as client:
    client.create_root_ca_key(
        private_label="root-ca-key",
        ceremony_reference=ceremony,
    )
    root_cert_pem = client.create_root_ca_cert(
        root_private_label="root-ca-key",
        subject_common_name="Example Root CA",
        organization="Example Org",
        country="US",
        ceremony_reference=ceremony,
    )

    client.create_intermediate_key(private_label="intermediate-ca-key")
    intermediate_csr_pem = client.create_csr(
        private_label="intermediate-ca-key",
        subject_common_name="Example Intermediate CA",
        organization="Example Org",
        country="US",
        is_ca=True,
        ca_path_length=0,
    )
    intermediate_cert_pem = client.sign_intermediate_csr(
        root_private_label="root-ca-key",
        root_certificate_pem=root_cert_pem,
        intermediate_csr_pem=intermediate_csr_pem,
        ceremony_reference=ceremony,
    )
```

## PKI CLI (CA/CSR operations)

Use `examples/hsm_cli.py --mode pki` for command-line PKI operations.

Current command groups:

- `keygen`
- `csr create`
- `cert sign`
- `sign`
- `verify`
- `rotation plan`

Role control during CLI usage:

- `export HSM_OPERATION_ROLE=ca` before CA issuance operations.
- `export HSM_OPERATION_ROLE=app` before `sign` / `verify` and app-side key/CSR tasks.

### 1) CA key generation

Create root and intermediate keys:

```bash
python3 examples/hsm_cli.py --mode pki keygen \
  --profile ca_root \
  --private-label root-ca-key \
  --ceremony-reference 2026-q1-root-ceremony

python3 examples/hsm_cli.py --mode pki keygen \
  --profile ca_intermediate \
  --private-label intermediate-ca-key
```

Create root self-signed certificate:

```bash
python3 examples/hsm_cli.py --mode pki cert sign \
  --cert-type root \
  --issuer-private-label root-ca-key \
  --subject-cn "Example Root CA" \
  --org "Example Org" \
  --country US \
  --ca-path-length 1 \
  --ceremony-reference 2026-q1-root-ceremony \
  --out root-ca.pem
```

### 2) CSR creation

Create intermediate CA CSR:

```bash
python3 examples/hsm_cli.py --mode pki csr create \
  --private-label intermediate-ca-key \
  --subject-cn "Example Intermediate CA" \
  --org "Example Org" \
  --country US \
  --is-ca \
  --ca-path-length 0 \
  --out intermediate-ca.csr.pem
```

Create mTLS server leaf CSR:

```bash
python3 examples/hsm_cli.py --mode pki csr create \
  --private-label mtls-server-key \
  --subject-cn "db.internal.example" \
  --org "Example Org" \
  --country US \
  --leaf-usage server \
  --dns db.internal.example \
  --out mtls-server.csr.pem
```

### 3) Certificate signing

Sign intermediate CSR with root key:

```bash
python3 examples/hsm_cli.py --mode pki cert sign \
  --cert-type intermediate \
  --issuer-private-label root-ca-key \
  --issuer-cert-file root-ca.pem \
  --csr-file intermediate-ca.csr.pem \
  --ceremony-reference 2026-q1-root-ceremony \
  --ca-path-length 0 \
  --out intermediate-ca.pem
```

Sign leaf CSR with intermediate and output full chain:

```bash
python3 examples/hsm_cli.py --mode pki cert sign \
  --cert-type leaf-server \
  --issuer-private-label intermediate-ca-key \
  --issuer-cert-file intermediate-ca.pem \
  --csr-file mtls-server.csr.pem \
  --leaf-private-label mtls-server-key \
  --root-cert-file root-ca.pem \
  --out mtls-server.pem \
  --chain-out mtls-server-chain.pem
```

Validate chain:

```bash
openssl verify -CAfile root-ca.pem -untrusted intermediate-ca.pem mtls-server.pem
```

### 4) Detached signature workflows

Sign a blob and write detached signature metadata:

```bash
python3 examples/hsm_cli.py --mode pki sign \
  --private-label app-signing-key \
  --algorithm rsa_pss_sha256 \
  --message "payload to sign" \
  --out detached-signature.json
```

Verify:

```bash
python3 examples/hsm_cli.py --mode pki verify \
  --public-label app-signing-key.pub \
  --signature-file detached-signature.json \
  --message "payload to sign"
```

Sign a precomputed digest:

```bash
python3 examples/hsm_cli.py --mode pki sign \
  --private-label app-signing-key \
  --algorithm rsa_pss_sha256 \
  --digest-hex "<sha256-hex>" \
  --out detached-digest-signature.json
```

### 5) Rotation plan scaffolding

Render a profile rotation plan:

```bash
python3 examples/hsm_cli.py --mode pki rotation plan \
  --profile signing \
  --base-label app-signing-key
```

## Confidentiality flow (public key encrypt, private key decrypt)

Use the dedicated example:

```bash
python3 examples/confidentiality_flow.py \
  --private-label app-confidentiality-rsa \
  --message "confidential payload"
```

What it does:

- Loads an existing RSA confidentiality keypair by label, or generates one.
- Encrypts with the public key.
- Decrypts with the private key.
- Prints ciphertext (base64) and recovered plaintext.

Try a specific algorithm:

```bash
python3 examples/confidentiality_flow.py \
  --algorithm rsa_pkcs1v15 \
  --message "confidential payload"
```

Supported algorithms:

- `rsa_oaep_sha1` (default in the example for broad compatibility)
- `rsa_oaep_sha256`
- `rsa_oaep_sha384`
- `rsa_pkcs1v15`

## Troubleshooting

If you see `ModuleNotFoundError: No module named 'pkcs11'`, your current Python interpreter does not have `python-pkcs11` installed.

```bash
python3 -m pip install -e .
```

Verify the dependency is visible to the same interpreter:

```bash
python3 -c "import sys, importlib.metadata as md; print(sys.executable, md.version('python-pkcs11'))"
```

## Integration testing (SoftHSM + pytest)

Install dev dependencies:

```bash
python3 -m pip install -e ".[dev]"
```

Run the SoftHSM integration test:

```bash
pytest -m integration -q
```

Run only the CA workflow tests:

```bash
pytest -q tests/test_softhsm_integration.py -k "root_ca_operation or root_and_intermediate_ca_workflow or mtls_leaf_issue"
```

Run only the PKI CLI workflow test:

```bash
pytest -q tests/test_softhsm_integration.py -k pki_cli_root_intermediate_leaf_and_sign_verify_workflow
```

Test behavior:

- Initializes an isolated SoftHSM token in a temporary directory.
- Generates a non-exportable AES key.
- Verifies encrypt/decrypt round-trip through the HSM client.
- Verifies AES-GCM with AAD when supported by the provider.
- Verifies versioned rotation (`-v0001`, `-v0002`) and latest-key lookup.
- Verifies AES key wrap/unwrap flows.
- Verifies asymmetric signing/verification for RSA and EC keys.
- Verifies asymmetric confidentiality encrypt/decrypt flows.
- Verifies root CA policy gate behavior and root/intermediate certificate chain flow.
- Verifies mTLS leaf issuance and root->intermediate->leaf chain validation.
- Verifies detached signature blob/digest workflows and role separation controls.
- Verifies PKI CLI operations (including unified mode dispatch) against SoftHSM.
- Skips cleanly if SoftHSM is not installed.

## Project layout

- `src/hsm_client/config.py`: env-based configuration loader.
- `src/hsm_client/asymmetric_profiles.py`: asymmetric key profile definitions.
- `src/hsm_client/x509_ops.py`: CSR and X.509 certificate construction/signing helpers.
- `src/hsm_client/logging_utils.py`: rotating file logging setup.
- `src/hsm_client/pkcs11_client.py`: PKCS#11 client wrapper.
- `examples/basic_flow.py`: end-to-end usage example.
- `examples/key_lifecycle.py`: key rotation and wrap/unwrap example.
- `examples/confidentiality_flow.py`: asymmetric confidentiality example.
- `examples/hsm_cli.py`: unified entrypoint for symmetric + PKI workflows.
- `examples/pki_cli.py`: PKI keygen/CSR/cert/sign/verify CLI workflows.
- `tests/test_softhsm_integration.py`: SoftHSM integration test.
- `tests/test_logging_utils.py`: logging setup test.

## Security notes

- Treat this as a baseline, then harden for production:
  - Restrict HSM network path and authentication policies.
  - Use per-service keys and rotation.
  - Enable audit logs and monitor for key usage anomalies.
- For new designs, prefer authenticated encryption (for example AES-GCM) if your HSM mechanism support is verified.
