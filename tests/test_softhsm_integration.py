from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from pathlib import Path

import pkcs11
import pytest

from hsm_client import HsmConfig, HsmOperationError, Pkcs11HsmClient

pytestmark = pytest.mark.integration


def _candidate_module_paths() -> list[Path]:
    paths: list[Path] = []

    env_path = os.environ.get("HSM_PKCS11_MODULE")
    if env_path:
        paths.append(Path(env_path))

    brew = shutil.which("brew")
    if brew:
        try:
            proc = subprocess.run(
                [brew, "--prefix", "softhsm"],
                check=True,
                capture_output=True,
                text=True,
            )
            prefix = proc.stdout.strip()
            if prefix:
                paths.append(Path(prefix) / "lib/softhsm/libsofthsm2.so")
        except subprocess.SubprocessError:
            pass

    paths.extend(
        [
            Path("/opt/homebrew/lib/softhsm/libsofthsm2.so"),
            Path("/usr/local/lib/softhsm/libsofthsm2.so"),
            Path("/usr/lib/softhsm/libsofthsm2.so"),
            Path("/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so"),
        ]
    )
    return paths


def _resolve_softhsm_module() -> Path | None:
    for candidate in _candidate_module_paths():
        if candidate.exists():
            return candidate
    return None


@pytest.fixture(scope="session")
def softhsm_runtime(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    util = shutil.which("softhsm2-util")
    if util is None:
        pytest.skip("softhsm2-util was not found. Install SoftHSM v2 for integration tests.")

    module_path = _resolve_softhsm_module()
    if module_path is None:
        pytest.skip(
            "SoftHSM PKCS#11 module was not found. Set HSM_PKCS11_MODULE to libsofthsm2.so."
        )

    runtime_dir = tmp_path_factory.mktemp("softhsm-runtime")
    tokens_dir = runtime_dir / "tokens"
    tokens_dir.mkdir()

    conf_path = runtime_dir / "softhsm2.conf"
    conf_path.write_text(
        "\n".join(
            [
                f"directories.tokendir = {tokens_dir}",
                "objectstore.backend = file",
                "log.level = ERROR",
                "",
            ]
        ),
        encoding="utf-8",
    )

    token_label = f"pytest-token-{uuid.uuid4().hex[:8]}"
    so_pin = "12345678"
    user_pin = "123456"

    env = os.environ.copy()
    env["SOFTHSM2_CONF"] = str(conf_path)

    proc = subprocess.run(
        [
            util,
            "--init-token",
            "--free",
            "--label",
            token_label,
            "--so-pin",
            so_pin,
            "--pin",
            user_pin,
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    if proc.returncode != 0:
        pytest.fail(
            "Failed to initialize SoftHSM token.\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )

    return {
        "module_path": str(module_path),
        "token_label": token_label,
        "user_pin": user_pin,
        "softhsm2_conf": str(conf_path),
    }


def test_generate_encrypt_decrypt_round_trip(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    key_label = f"pytest-key-{uuid.uuid4().hex[:8]}"
    plaintext = b"integration-test-payload"

    with Pkcs11HsmClient(config) as client:
        assert client.get_aes_key(key_label) is None
        key = client.generate_aes_key(key_label, bits=256)
        payload = client.encrypt_aes(key, plaintext, prefer_gcm=True)
        recovered = client.decrypt_aes(key, payload)
        assert recovered == plaintext
        assert payload.mechanism in {"AES_GCM", "AES_CBC_PAD"}
        if payload.mechanism == "AES_GCM":
            assert len(payload.iv_or_nonce) == 12
        else:
            assert len(payload.iv_or_nonce) == 16
        assert client.get_aes_key(key_label) is not None


def test_encrypt_decrypt_aes_gcm_with_aad(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    key_label = f"pytest-gcm-key-{uuid.uuid4().hex[:8]}"
    plaintext = b"integration-test-gcm-payload"
    aad = b"tenant=dev;purpose=integration-test"

    with Pkcs11HsmClient(config) as client:
        key = client.generate_aes_key(key_label, bits=256)
        try:
            payload = client.encrypt_aes(key, plaintext, aad=aad, prefer_gcm=True)
        except HsmOperationError as exc:
            if isinstance(
                exc.__cause__,
                (
                    pkcs11.exceptions.MechanismInvalid,
                    pkcs11.exceptions.MechanismParamInvalid,
                    pkcs11.exceptions.FunctionNotSupported,
                ),
            ):
                pytest.skip("AES-GCM is unavailable in this PKCS#11 provider.")
            raise

        assert payload.mechanism == "AES_GCM"
        recovered = client.decrypt_aes(key, payload)
        assert recovered == plaintext


def test_rotate_aes_key_versions(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    base_label = f"app-rotating-key-{uuid.uuid4().hex[:6]}"

    with Pkcs11HsmClient(config) as client:
        first_meta, _first_key = client.rotate_aes_key(base_label, bits=256)
        second_meta, second_key = client.rotate_aes_key(base_label, bits=256)

        assert first_meta.label == f"{base_label}-v0001"
        assert second_meta.label == f"{base_label}-v0002"
        versions = client.list_aes_key_versions(base_label)
        assert [item.version for item in versions] == [1, 2]

        latest = client.get_latest_aes_key(base_label)
        assert latest is not None
        latest_meta, latest_key = latest
        assert latest_meta.version == 2
        assert latest_meta.label == second_meta.label

        payload = client.encrypt_aes(second_key, b"rotation-payload")
        assert client.decrypt_aes(latest_key, payload) == b"rotation-payload"


def test_wrap_unwrap_aes_key(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    source_label = f"transfer-src-{uuid.uuid4().hex[:8]}"
    kek_label = f"transfer-kek-{uuid.uuid4().hex[:8]}"
    destination_label = f"transfer-dst-{uuid.uuid4().hex[:8]}"

    with Pkcs11HsmClient(config) as client:
        source_key = client.generate_aes_key(source_label, bits=256, extractable=True)
        kek = client.generate_aes_kek(kek_label, bits=256)

        try:
            wrapped = client.wrap_aes_key(kek, source_key)
            unwrapped_key = client.unwrap_aes_key(kek, wrapped, label=destination_label)
        except HsmOperationError as exc:
            if isinstance(
                exc.__cause__,
                (
                    pkcs11.exceptions.MechanismInvalid,
                    pkcs11.exceptions.MechanismParamInvalid,
                    pkcs11.exceptions.FunctionNotSupported,
                ),
            ):
                pytest.skip("AES key wrap/unwrap is unavailable in this PKCS#11 provider.")
            raise

        payload = client.encrypt_aes(unwrapped_key, b"wrapped-transfer-check")
        assert client.decrypt_aes(unwrapped_key, payload) == b"wrapped-transfer-check"


def test_generate_rsa_keypair_and_sign_verify(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    private_label = f"rsa-priv-{uuid.uuid4().hex[:8]}"
    public_label = f"rsa-pub-{uuid.uuid4().hex[:8]}"
    payload = b"rsa-signing-payload"

    with Pkcs11HsmClient(config) as client:
        client.generate_rsa_keypair(
            private_label=private_label,
            public_label=public_label,
            bits=2048,
            extractable=False,
        )
        private_key = client.get_private_key(private_label, key_type=pkcs11.KeyType.RSA)
        public_key = client.get_public_key(public_label, key_type=pkcs11.KeyType.RSA)
        assert private_key is not None
        assert public_key is not None

        for algorithm in (
            "rsa_pkcs1v15_sha256",
            "rsa_pkcs1v15_sha384",
            "rsa_pss_sha256",
            "rsa_pss_sha384",
        ):
            signature = client.sign(private_key, payload, algorithm=algorithm)
            assert client.verify(public_key, payload, signature, algorithm=algorithm)
            assert not client.verify(
                public_key,
                payload + b"-tampered",
                signature,
                algorithm=algorithm,
            )


def test_generate_ec_keypair_from_profile_and_sign_verify(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    mtls_label = f"mtls-ec-priv-{uuid.uuid4().hex[:8]}"
    ca_label = f"ca-ec-priv-{uuid.uuid4().hex[:8]}"

    with Pkcs11HsmClient(config) as client:
        profiles = set(client.list_key_profiles())
        assert {"ca_root", "ca_intermediate", "mtls_server", "mtls_client", "signing"}.issubset(
            profiles
        )

        mtls_public, mtls_private = client.generate_keypair_for_profile(
            "mtls_server",
            private_label=mtls_label,
        )
        mtls_payload = b"mtls-ecdsa-payload"
        mtls_signature = client.sign(mtls_private, mtls_payload, algorithm="ecdsa_sha256")
        assert client.verify(mtls_public, mtls_payload, mtls_signature, algorithm="ecdsa_sha256")

        ca_public, ca_private = client.generate_keypair_for_profile(
            "ca_root",
            private_label=ca_label,
        )
        ca_payload = b"ca-ecdsa-payload"
        ca_signature = client.sign(ca_private, ca_payload, algorithm="ecdsa_sha384")
        assert client.verify(ca_public, ca_payload, ca_signature, algorithm="ecdsa_sha384")

        loaded_private = client.get_private_key(mtls_label, key_type=pkcs11.KeyType.EC)
        loaded_public = client.get_public_key(f"{mtls_label}.pub", key_type=pkcs11.KeyType.EC)
        assert loaded_private is not None
        assert loaded_public is not None

        with pytest.raises(ValueError):
            client.generate_keypair_for_profile(
                "unknown-profile",
                private_label="does-not-matter",
            )


def test_asymmetric_confidentiality_encrypt_decrypt(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    private_label = f"rsa-conf-priv-{uuid.uuid4().hex[:8]}"
    public_label = f"rsa-conf-pub-{uuid.uuid4().hex[:8]}"
    plaintext = b"confidential-message"

    with Pkcs11HsmClient(config) as client:
        public_key, private_key = client.generate_rsa_keypair(
            private_label=private_label,
            public_label=public_label,
            bits=2048,
            extractable=False,
            allow_sign=False,
            allow_verify=False,
            allow_encrypt=True,
            allow_decrypt=True,
        )

        # Always expected to work with PKCS#1 v1.5 when RSA encryption is enabled.
        ciphertext_pkcs1 = client.encrypt_confidential(
            public_key,
            plaintext,
            algorithm="rsa_pkcs1v15",
        )
        recovered_pkcs1 = client.decrypt_confidential(
            private_key,
            ciphertext_pkcs1,
            algorithm="rsa_pkcs1v15",
        )
        assert recovered_pkcs1 == plaintext

        # OAEP-SHA1 is widely supported and used as compatibility baseline here.
        ciphertext_oaep = client.encrypt_confidential(
            public_key,
            plaintext,
            algorithm="rsa_oaep_sha1",
        )
        recovered_oaep = client.decrypt_confidential(
            private_key,
            ciphertext_oaep,
            algorithm="rsa_oaep_sha1",
        )
        assert recovered_oaep == plaintext

        # Wrong algorithm for decrypt should not yield the original plaintext.
        # Some providers raise immediately, others may return undecodable bytes.
        try:
            mismatched = client.decrypt_confidential(
                private_key,
                ciphertext_oaep,
                algorithm="rsa_pkcs1v15",
            )
        except HsmOperationError:
            pass
        else:
            assert mismatched != plaintext
