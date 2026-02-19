from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
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


def test_detached_sign_blob_and_sign_digest(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_OPERATION_ROLE", "app")

    config = HsmConfig.from_env()
    private_label = f"rsa-detached-priv-{uuid.uuid4().hex[:8]}"
    public_label = f"rsa-detached-pub-{uuid.uuid4().hex[:8]}"
    payload = b"detached-signature-payload"

    with Pkcs11HsmClient(config) as client:
        client.generate_rsa_keypair(
            private_label=private_label,
            public_label=public_label,
            bits=2048,
            extractable=False,
            allow_sign=True,
            allow_verify=True,
        )

        detached_blob = client.sign_blob(
            private_label=private_label,
            blob=payload,
            algorithm="rsa_pss_sha256",
        )
        encoded = detached_blob.to_json()
        decoded = type(detached_blob).from_json(encoded)
        assert decoded.algorithm == "rsa_pss_sha256"
        assert decoded.hash_algorithm == "sha256"
        assert decoded.input_type == "blob"
        assert client.verify_blob(
            public_label=public_label,
            blob=payload,
            detached_signature=decoded,
        )
        assert not client.verify_blob(
            public_label=public_label,
            blob=payload + b"-tampered",
            detached_signature=decoded,
        )

        digest = hashlib.sha256(payload).digest()
        detached_digest = client.sign_digest(
            private_label=private_label,
            digest=digest,
            algorithm="rsa_pss_sha256",
        )
        assert detached_digest.input_type == "digest"
        assert client.verify_digest(
            public_label=public_label,
            digest=digest,
            detached_signature=detached_digest,
        )
        with pytest.raises(ValueError):
            client.sign_digest(
                private_label=private_label,
                digest=b"short",
                algorithm="rsa_pss_sha256",
            )


def test_profile_rotation_plan_scaffolding(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])

    config = HsmConfig.from_env()
    base_label = f"app-signing-{uuid.uuid4().hex[:6]}"
    first_label = f"{base_label}-v0001"
    first_public = f"{first_label}.pub"

    with Pkcs11HsmClient(config) as client:
        static_plan = client.build_profile_rotation_plan(
            "signing",
            base_label,
            current_version=3,
        )
        assert static_plan.next_label == f"{base_label}-v0004"
        assert static_plan.owner_role == "app"
        assert static_plan.recommended_interval_days > 0

        client.generate_keypair_for_profile(
            "signing",
            private_label=first_label,
            public_label=first_public,
        )
        token_plan = client.build_profile_rotation_plan_from_token(
            "signing",
            base_label,
        )
        assert token_plan.current_version == 1
        assert token_plan.next_version == 2
        assert token_plan.next_label == f"{base_label}-v0002"


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


def test_root_ca_operation_requires_policy_gate(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.delenv("HSM_ALLOW_ROOT_CA", raising=False)

    config = HsmConfig.from_env()
    denied_label = f"root-denied-{uuid.uuid4().hex[:8]}"
    allowed_label = f"root-allowed-{uuid.uuid4().hex[:8]}"

    with Pkcs11HsmClient(config) as client:
        with pytest.raises(HsmOperationError):
            client.create_root_ca_key(
                private_label=denied_label,
                ceremony_reference="pytest-ceremony",
            )

        monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")
        _public_key, private_key = client.create_root_ca_key(
            private_label=allowed_label,
            ceremony_reference="pytest-ceremony",
        )
        assert private_key[pkcs11.Attribute.EXTRACTABLE] is False


def test_role_separation_for_ca_vs_app_operations(
    softhsm_runtime: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")

    config = HsmConfig.from_env()
    signing_label = f"app-signing-{uuid.uuid4().hex[:8]}"

    with Pkcs11HsmClient(config) as client:
        client.generate_keypair_for_profile("signing", private_label=signing_label)

        monkeypatch.setenv("HSM_OPERATION_ROLE", "ca")
        with pytest.raises(HsmOperationError):
            client.sign_blob(
                private_label=signing_label,
                blob=b"payload",
                algorithm="rsa_pss_sha256",
            )

        monkeypatch.setenv("HSM_OPERATION_ROLE", "app")
        with pytest.raises(HsmOperationError):
            client.create_intermediate_key(
                private_label=f"int-denied-{uuid.uuid4().hex[:8]}"
            )


def test_root_and_intermediate_ca_workflow(
    softhsm_runtime: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")

    config = HsmConfig.from_env()
    ceremony_reference = f"pytest-ca-{uuid.uuid4().hex[:8]}"
    root_private_label = f"root-ca-priv-{uuid.uuid4().hex[:8]}"
    intermediate_private_label = f"int-ca-priv-{uuid.uuid4().hex[:8]}"

    with Pkcs11HsmClient(config) as client:
        client.create_root_ca_key(
            private_label=root_private_label,
            ceremony_reference=ceremony_reference,
        )
        root_cert_pem = client.create_root_ca_cert(
            root_private_label=root_private_label,
            subject_common_name="Pytest Root CA",
            organization="Pytest Org",
            country="US",
            ceremony_reference=ceremony_reference,
            validity_days=3650,
            path_length=1,
        )

        client.create_intermediate_key(private_label=intermediate_private_label)
        intermediate_csr_pem = client.create_csr(
            private_label=intermediate_private_label,
            subject_common_name="Pytest Intermediate CA",
            organization="Pytest Org",
            country="US",
            is_ca=True,
            ca_path_length=0,
        )
        intermediate_cert_pem = client.sign_intermediate_csr(
            root_private_label=root_private_label,
            root_certificate_pem=root_cert_pem,
            intermediate_csr_pem=intermediate_csr_pem,
            ceremony_reference=ceremony_reference,
            validity_days=1825,
            path_length=0,
        )

    root_cert_path = tmp_path / "root-ca.pem"
    intermediate_csr_path = tmp_path / "intermediate.csr.pem"
    intermediate_cert_path = tmp_path / "intermediate-ca.pem"
    root_cert_path.write_bytes(root_cert_pem)
    intermediate_csr_path.write_bytes(intermediate_csr_pem)
    intermediate_cert_path.write_bytes(intermediate_cert_pem)

    csr_verify = subprocess.run(
        [
            "openssl",
            "req",
            "-in",
            str(intermediate_csr_path),
            "-verify",
            "-noout",
        ],
        capture_output=True,
        text=True,
    )
    assert csr_verify.returncode == 0, (
        f"CSR signature verification failed.\n"
        f"stdout:\n{csr_verify.stdout}\n"
        f"stderr:\n{csr_verify.stderr}"
    )
    assert "verify OK" in f"{csr_verify.stdout}\n{csr_verify.stderr}"

    chain_verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_cert_path),
            str(intermediate_cert_path),
        ],
        capture_output=True,
        text=True,
    )
    assert chain_verify.returncode == 0, (
        f"CA chain verification failed.\n"
        f"stdout:\n{chain_verify.stdout}\n"
        f"stderr:\n{chain_verify.stderr}"
    )
    assert f"{intermediate_cert_path}: OK" in chain_verify.stdout


def test_mtls_leaf_issue_and_chain_validation(
    softhsm_runtime: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")

    config = HsmConfig.from_env()
    ceremony_reference = f"pytest-mtls-ca-{uuid.uuid4().hex[:8]}"
    root_private_label = f"root-mtls-priv-{uuid.uuid4().hex[:8]}"
    intermediate_private_label = f"int-mtls-priv-{uuid.uuid4().hex[:8]}"
    leaf_private_label = f"leaf-mtls-priv-{uuid.uuid4().hex[:8]}"

    monkeypatch.setenv("HSM_OPERATION_ROLE", "ca")
    with Pkcs11HsmClient(config) as client:
        client.create_root_ca_key(
            private_label=root_private_label,
            ceremony_reference=ceremony_reference,
        )
        root_cert_pem = client.create_root_ca_cert(
            root_private_label=root_private_label,
            subject_common_name="Pytest mTLS Root",
            organization="Pytest Org",
            country="US",
            ceremony_reference=ceremony_reference,
            validity_days=3650,
            path_length=1,
        )
        client.create_intermediate_key(private_label=intermediate_private_label)
        intermediate_csr_pem = client.create_csr(
            private_label=intermediate_private_label,
            subject_common_name="Pytest mTLS Intermediate",
            organization="Pytest Org",
            country="US",
            is_ca=True,
            ca_path_length=0,
        )
        intermediate_cert_pem = client.sign_intermediate_csr(
            root_private_label=root_private_label,
            root_certificate_pem=root_cert_pem,
            intermediate_csr_pem=intermediate_csr_pem,
            ceremony_reference=ceremony_reference,
            validity_days=1825,
            path_length=0,
        )

    monkeypatch.setenv("HSM_OPERATION_ROLE", "app")
    with Pkcs11HsmClient(config) as client:
        leaf_bundle = client.generate_mtls_leaf_key_and_csr(
            profile_name="mtls_server",
            private_label=leaf_private_label,
            subject_common_name="db.internal.example",
            organization="Pytest Org",
            country="US",
            dns_names=["db.internal.example"],
        )
        assert leaf_bundle.private_key_label == leaf_private_label
        assert b"BEGIN CERTIFICATE REQUEST" in leaf_bundle.csr_pem

    monkeypatch.setenv("HSM_OPERATION_ROLE", "ca")
    with Pkcs11HsmClient(config) as client:
        issued = client.sign_mtls_leaf_csr(
            profile_name="mtls_server",
            leaf_private_label=leaf_bundle.private_key_label,
            leaf_public_label=leaf_bundle.public_key_label,
            leaf_csr_pem=leaf_bundle.csr_pem,
            intermediate_private_label=intermediate_private_label,
            intermediate_certificate_pem=intermediate_cert_pem,
            root_certificate_pem=root_cert_pem,
            validity_days=397,
            mtls_usage="server",
        )

    root_path = tmp_path / "mtls-root.pem"
    intermediate_path = tmp_path / "mtls-intermediate.pem"
    leaf_path = tmp_path / "mtls-leaf.pem"
    chain_path = tmp_path / "mtls-chain.pem"
    root_path.write_bytes(root_cert_pem)
    intermediate_path.write_bytes(intermediate_cert_pem)
    leaf_path.write_bytes(issued.certificate_pem)
    chain_path.write_bytes(issued.certificate_chain_pem)

    chain_verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_path),
            "-untrusted",
            str(intermediate_path),
            str(leaf_path),
        ],
        capture_output=True,
        text=True,
    )
    assert chain_verify.returncode == 0, (
        f"Leaf chain verification failed.\n"
        f"stdout:\n{chain_verify.stdout}\n"
        f"stderr:\n{chain_verify.stderr}"
    )
    assert f"{leaf_path}: OK" in chain_verify.stdout
    assert b"BEGIN CERTIFICATE" in issued.certificate_chain_pem


def test_pki_cli_root_intermediate_leaf_and_sign_verify_workflow(
    softhsm_runtime: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")

    cli_script = Path(__file__).resolve().parents[1] / "examples" / "pki_cli.py"
    assert cli_script.exists()

    ceremony_reference = f"pytest-cli-ca-{uuid.uuid4().hex[:8]}"
    root_private_label = f"root-cli-priv-{uuid.uuid4().hex[:8]}"
    intermediate_private_label = f"int-cli-priv-{uuid.uuid4().hex[:8]}"
    leaf_private_label = f"leaf-cli-priv-{uuid.uuid4().hex[:8]}"
    signing_private_label = f"sig-cli-priv-{uuid.uuid4().hex[:8]}"

    root_cert_path = tmp_path / "root-cli.pem"
    intermediate_csr_path = tmp_path / "intermediate-cli.csr.pem"
    intermediate_cert_path = tmp_path / "intermediate-cli.pem"
    leaf_csr_path = tmp_path / "leaf-cli.csr.pem"
    leaf_cert_path = tmp_path / "leaf-cli.pem"
    leaf_chain_path = tmp_path / "leaf-cli-chain.pem"
    detached_signature_path = tmp_path / "detached-signature.json"

    def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(
            [sys.executable, str(cli_script), *args],
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )
        assert proc.returncode == 0, (
            f"CLI command failed: {' '.join(args)}\n"
            f"stdout:\n{proc.stdout}\n"
            f"stderr:\n{proc.stderr}"
        )
        return proc

    monkeypatch.setenv("HSM_OPERATION_ROLE", "ca")
    run_cli(
        "keygen",
        "--profile",
        "ca_root",
        "--private-label",
        root_private_label,
        "--ceremony-reference",
        ceremony_reference,
    )
    run_cli(
        "cert",
        "sign",
        "--cert-type",
        "root",
        "--issuer-private-label",
        root_private_label,
        "--subject-cn",
        "Pytest CLI Root CA",
        "--org",
        "Pytest Org",
        "--country",
        "US",
        "--ca-path-length",
        "1",
        "--ceremony-reference",
        ceremony_reference,
        "--out",
        str(root_cert_path),
    )

    run_cli(
        "keygen",
        "--profile",
        "ca_intermediate",
        "--private-label",
        intermediate_private_label,
    )
    run_cli(
        "csr",
        "create",
        "--private-label",
        intermediate_private_label,
        "--subject-cn",
        "Pytest CLI Intermediate CA",
        "--org",
        "Pytest Org",
        "--country",
        "US",
        "--is-ca",
        "--ca-path-length",
        "0",
        "--out",
        str(intermediate_csr_path),
    )
    run_cli(
        "cert",
        "sign",
        "--cert-type",
        "intermediate",
        "--issuer-private-label",
        root_private_label,
        "--issuer-cert-file",
        str(root_cert_path),
        "--csr-file",
        str(intermediate_csr_path),
        "--ceremony-reference",
        ceremony_reference,
        "--ca-path-length",
        "0",
        "--out",
        str(intermediate_cert_path),
    )

    monkeypatch.setenv("HSM_OPERATION_ROLE", "app")
    run_cli(
        "keygen",
        "--profile",
        "mtls_server",
        "--private-label",
        leaf_private_label,
    )
    run_cli(
        "csr",
        "create",
        "--private-label",
        leaf_private_label,
        "--subject-cn",
        "db.internal.example",
        "--org",
        "Pytest Org",
        "--country",
        "US",
        "--leaf-usage",
        "server",
        "--dns",
        "db.internal.example",
        "--out",
        str(leaf_csr_path),
    )

    monkeypatch.setenv("HSM_OPERATION_ROLE", "ca")
    run_cli(
        "cert",
        "sign",
        "--cert-type",
        "leaf-server",
        "--issuer-private-label",
        intermediate_private_label,
        "--issuer-cert-file",
        str(intermediate_cert_path),
        "--csr-file",
        str(leaf_csr_path),
        "--leaf-private-label",
        leaf_private_label,
        "--root-cert-file",
        str(root_cert_path),
        "--out",
        str(leaf_cert_path),
        "--chain-out",
        str(leaf_chain_path),
    )

    monkeypatch.setenv("HSM_OPERATION_ROLE", "app")
    run_cli(
        "keygen",
        "--profile",
        "signing",
        "--private-label",
        signing_private_label,
    )
    run_cli(
        "sign",
        "--private-label",
        signing_private_label,
        "--message",
        "cli-signature-payload",
        "--algorithm",
        "rsa_pss_sha256",
        "--out",
        str(detached_signature_path),
    )
    verify_proc = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "verify",
            "--public-label",
            f"{signing_private_label}.pub",
            "--signature-file",
            str(detached_signature_path),
            "--message",
            "cli-signature-payload",
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert verify_proc.returncode == 0, (
        f"CLI verify failed.\nstdout:\n{verify_proc.stdout}\nstderr:\n{verify_proc.stderr}"
    )
    verify_payload = json.loads(verify_proc.stdout)
    assert verify_payload["verified"] is True

    csr_verify = subprocess.run(
        [
            "openssl",
            "req",
            "-in",
            str(intermediate_csr_path),
            "-verify",
            "-noout",
        ],
        capture_output=True,
        text=True,
    )
    assert csr_verify.returncode == 0, (
        f"CSR signature verification failed.\n"
        f"stdout:\n{csr_verify.stdout}\n"
        f"stderr:\n{csr_verify.stderr}"
    )
    assert "verify OK" in f"{csr_verify.stdout}\n{csr_verify.stderr}"

    chain_verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_cert_path),
            str(intermediate_cert_path),
        ],
        capture_output=True,
        text=True,
    )
    assert chain_verify.returncode == 0, (
        f"CA chain verification failed.\n"
        f"stdout:\n{chain_verify.stdout}\n"
        f"stderr:\n{chain_verify.stderr}"
    )
    assert f"{intermediate_cert_path}: OK" in chain_verify.stdout

    leaf_chain_verify = subprocess.run(
        [
            "openssl",
            "verify",
            "-CAfile",
            str(root_cert_path),
            "-untrusted",
            str(intermediate_cert_path),
            str(leaf_cert_path),
        ],
        capture_output=True,
        text=True,
    )
    assert leaf_chain_verify.returncode == 0, (
        f"Leaf chain verification failed.\n"
        f"stdout:\n{leaf_chain_verify.stdout}\n"
        f"stderr:\n{leaf_chain_verify.stderr}"
    )
    assert f"{leaf_cert_path}: OK" in leaf_chain_verify.stdout


def test_unified_hsm_cli_mode_dispatch(
    softhsm_runtime: dict[str, str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("SOFTHSM2_CONF", softhsm_runtime["softhsm2_conf"])
    monkeypatch.setenv("HSM_PKCS11_MODULE", softhsm_runtime["module_path"])
    monkeypatch.setenv("HSM_TOKEN_LABEL", softhsm_runtime["token_label"])
    monkeypatch.setenv("HSM_USER_PIN", softhsm_runtime["user_pin"])
    monkeypatch.setenv("HSM_ALLOW_ROOT_CA", "true")

    cli_script = Path(__file__).resolve().parents[1] / "examples" / "hsm_cli.py"
    assert cli_script.exists()

    payload_path = tmp_path / "unified-symmetric.payload.json"
    plaintext = "unified-dispatch-payload"

    encrypt_proc = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "--mode",
            "symmetric",
            "--message",
            plaintext,
            "--out",
            str(payload_path),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert encrypt_proc.returncode == 0, (
        "Unified symmetric encrypt command failed.\n"
        f"stdout:\n{encrypt_proc.stdout}\n"
        f"stderr:\n{encrypt_proc.stderr}"
    )

    decrypt_proc = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "--mode",
            "symmetric",
            "--decrypt",
            "--payload-file",
            str(payload_path),
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert decrypt_proc.returncode == 0, (
        "Unified symmetric decrypt command failed.\n"
        f"stdout:\n{decrypt_proc.stdout}\n"
        f"stderr:\n{decrypt_proc.stderr}"
    )
    assert plaintext in decrypt_proc.stdout

    monkeypatch.setenv("HSM_OPERATION_ROLE", "app")
    signing_private_label = f"unified-signing-{uuid.uuid4().hex[:8]}"
    pki_proc = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "--mode",
            "pki",
            "keygen",
            "--profile",
            "signing",
            "--private-label",
            signing_private_label,
        ],
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )
    assert pki_proc.returncode == 0, (
        "Unified PKI keygen command failed.\n"
        f"stdout:\n{pki_proc.stdout}\n"
        f"stderr:\n{pki_proc.stderr}"
    )
    parsed = json.loads(pki_proc.stdout)
    assert parsed["operation"] == "keygen"
    assert parsed["profile"] == "signing"


def test_unified_hsm_cli_mode_specific_help() -> None:
    cli_script = Path(__file__).resolve().parents[1] / "examples" / "hsm_cli.py"
    assert cli_script.exists()

    symmetric_help = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "--mode",
            "symmetric",
            "--help",
        ],
        capture_output=True,
        text=True,
    )
    assert symmetric_help.returncode == 0
    assert "--encrypt" in symmetric_help.stdout
    assert "--decrypt" in symmetric_help.stdout

    pki_help = subprocess.run(
        [
            sys.executable,
            str(cli_script),
            "--mode",
            "pki",
            "--help",
        ],
        capture_output=True,
        text=True,
    )
    assert pki_help.returncode == 0
    assert "{keygen,csr,cert,sign,verify,rotation}" in pki_help.stdout
