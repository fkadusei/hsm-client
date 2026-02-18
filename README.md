# hsm-client

Minimal Python starter for connecting to an HSM over `PKCS#11` and performing symmetric cryptography without exporting key bytes.

## What this starter does

- Loads PKCS#11 module and opens an authenticated session.
- Finds an AES key by label or creates one if missing.
- Encrypts and decrypts data using key handles in the HSM.
- Prefers AES-GCM and falls back to AES-CBC-PAD when GCM is unavailable.
- Enforces non-exportable keys by default (`CKA_EXTRACTABLE=false`).
- Supports key lifecycle workflows: versioned rotation and key wrap/unwrap.

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

## Run example

```bash
python3 examples/basic_flow.py --key-label app-aes-key --message "test payload"
```

Optional AAD (used only when AES-GCM is selected):

```bash
python3 examples/basic_flow.py --key-label app-aes-key --message "test payload" --aad "request-id=abc123"
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

Test behavior:

- Initializes an isolated SoftHSM token in a temporary directory.
- Generates a non-exportable AES key.
- Verifies encrypt/decrypt round-trip through the HSM client.
- Verifies AES-GCM with AAD when supported by the provider.
- Verifies versioned rotation (`-v0001`, `-v0002`) and latest-key lookup.
- Verifies AES key wrap/unwrap flows.
- Skips cleanly if SoftHSM is not installed.

## Project layout

- `src/hsm_client/config.py`: env-based configuration loader.
- `src/hsm_client/pkcs11_client.py`: PKCS#11 client wrapper.
- `examples/basic_flow.py`: end-to-end usage example.
- `examples/key_lifecycle.py`: key rotation and wrap/unwrap example.
- `tests/test_softhsm_integration.py`: SoftHSM integration test.

## Security notes

- Treat this as a baseline, then harden for production:
  - Restrict HSM network path and authentication policies.
  - Use per-service keys and rotation.
  - Enable audit logs and monitor for key usage anomalies.
- For new designs, prefer authenticated encryption (for example AES-GCM) if your HSM mechanism support is verified.
