from __future__ import annotations

import base64
import json
import logging
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

import pkcs11
import pkcs11.util.ec as ec_util
from pkcs11 import Attribute, KeyType, Mechanism, MGF, ObjectClass

from .asymmetric_profiles import (
    AsymmetricKeyProfile,
    KeyRotationPlan,
    build_rotation_plan,
    get_key_profile,
    list_key_profiles,
)
from .config import HsmConfig
from .exceptions import HsmOperationError
from .x509_ops import (
    build_distinguished_name,
    build_ca_csr_extensions,
    build_leaf_csr_extensions,
    create_certificate_signing_request,
    create_self_signed_ca_certificate,
    default_x509_signing_algorithm_for_key,
    dump_certificate_pem,
    dump_csr_pem,
    load_certificate,
    load_certificate_signing_request,
    pkcs11_public_key_to_public_key_info,
    sign_csr_as_ca,
    sign_csr_as_leaf,
)


def _format_exception(exc: Exception) -> str:
    details = str(exc).strip()
    if not details and getattr(exc, "args", None):
        details = ", ".join(str(a) for a in exc.args if a)
    if details:
        return f"{type(exc).__name__}: {details}"
    return type(exc).__name__


_GCM_FALLBACK_EXCEPTIONS = (
    pkcs11.exceptions.MechanismInvalid,
    pkcs11.exceptions.MechanismParamInvalid,
    pkcs11.exceptions.FunctionNotSupported,
)

_logger = logging.getLogger("hsm_client.client")


@dataclass(frozen=True)
class AesCiphertext:
    """
    Encrypted payload metadata returned by encrypt_aes().

    For AES_GCM, iv_or_nonce contains a 12-byte nonce.
    For AES_CBC_PAD, iv_or_nonce contains a 16-byte IV.
    """

    mechanism: str
    iv_or_nonce: bytes
    ciphertext: bytes
    aad: bytes | None = None
    tag_bits: int | None = None


@dataclass(frozen=True)
class VersionedAesKey:
    """Metadata for a versioned AES key label."""

    base_label: str
    version: int
    label: str


@dataclass(frozen=True)
class SignatureAlgorithmSpec:
    """PKCS#11 mechanism mapping for a signing algorithm."""

    key_type: KeyType
    mechanism: Mechanism
    mechanism_param: tuple[Mechanism, MGF, int] | None = None


@dataclass(frozen=True)
class AsymmetricEncryptionAlgorithmSpec:
    """PKCS#11 mechanism mapping for asymmetric confidentiality operations."""

    key_type: KeyType
    mechanism: Mechanism
    mechanism_param: tuple[Mechanism, MGF, bytes | None] | None = None


@dataclass(frozen=True)
class DigestSignatureAlgorithmSpec:
    """PKCS#11 mechanism mapping for digest-level signatures."""

    key_type: KeyType
    mechanism: Mechanism
    digest_name: str
    digest_size: int
    mechanism_param: tuple[Mechanism, MGF, int] | None = None
    digest_info_prefix: bytes | None = None


@dataclass(frozen=True)
class DetachedSignature:
    """Detached signature with explicit metadata for transport and verification."""

    algorithm: str
    hash_algorithm: str
    key_label: str
    input_type: str
    signature: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "version": "1",
            "algorithm": self.algorithm,
            "hash_algorithm": self.hash_algorithm,
            "key_label": self.key_label,
            "input_type": self.input_type,
            "signature_b64": base64.b64encode(self.signature).decode("ascii"),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "DetachedSignature":
        required = {"algorithm", "hash_algorithm", "key_label", "input_type", "signature_b64"}
        missing = [field for field in sorted(required) if field not in payload]
        if missing:
            raise ValueError(f"Detached signature payload missing fields: {', '.join(missing)}")
        raw = payload["signature_b64"]
        if not isinstance(raw, str):
            raise ValueError("signature_b64 must be a string.")
        try:
            signature = base64.b64decode(raw.encode("ascii"), validate=True)
        except Exception as exc:
            raise ValueError("Invalid base64 for signature_b64.") from exc
        return cls(
            algorithm=str(payload["algorithm"]),
            hash_algorithm=str(payload["hash_algorithm"]),
            key_label=str(payload["key_label"]),
            input_type=str(payload["input_type"]),
            signature=signature,
        )

    @classmethod
    def from_json(cls, payload: str) -> "DetachedSignature":
        try:
            loaded = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError("Detached signature payload is not valid JSON.") from exc
        if not isinstance(loaded, dict):
            raise ValueError("Detached signature payload must be a JSON object.")
        return cls.from_dict(loaded)


@dataclass(frozen=True)
class IssuedMtlsLeaf:
    """Result object for mTLS leaf issuance workflows."""

    profile_name: str
    private_key_label: str
    public_key_label: str
    csr_pem: bytes
    certificate_pem: bytes
    certificate_chain_pem: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "profile_name": self.profile_name,
            "private_key_label": self.private_key_label,
            "public_key_label": self.public_key_label,
            "csr_pem": self.csr_pem.decode("utf-8"),
            "certificate_pem": self.certificate_pem.decode("utf-8"),
            "certificate_chain_pem": self.certificate_chain_pem.decode("utf-8"),
        }


@dataclass(frozen=True)
class MtlsLeafCsrBundle:
    """Result object for mTLS keypair generation + CSR creation."""

    profile_name: str
    private_key_label: str
    public_key_label: str
    csr_pem: bytes

    def to_dict(self) -> dict[str, str]:
        return {
            "profile_name": self.profile_name,
            "private_key_label": self.private_key_label,
            "public_key_label": self.public_key_label,
            "csr_pem": self.csr_pem.decode("utf-8"),
        }

SIGNATURE_ALGORITHM_SPECS: dict[str, SignatureAlgorithmSpec] = {
    "rsa_pkcs1v15_sha256": SignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.SHA256_RSA_PKCS,
    ),
    "rsa_pkcs1v15_sha384": SignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.SHA384_RSA_PKCS,
    ),
    "rsa_pss_sha256": SignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.SHA256_RSA_PKCS_PSS,
        mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32),
    ),
    "rsa_pss_sha384": SignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.SHA384_RSA_PKCS_PSS,
        mechanism_param=(Mechanism.SHA384, MGF.SHA384, 48),
    ),
    "ecdsa_sha256": SignatureAlgorithmSpec(
        key_type=KeyType.EC,
        mechanism=Mechanism.ECDSA_SHA256,
    ),
    "ecdsa_sha384": SignatureAlgorithmSpec(
        key_type=KeyType.EC,
        mechanism=Mechanism.ECDSA_SHA384,
    ),
}

ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS: dict[str, AsymmetricEncryptionAlgorithmSpec] = {
    "rsa_oaep_sha1": AsymmetricEncryptionAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(Mechanism.SHA_1, MGF.SHA1, None),
    ),
    "rsa_oaep_sha256": AsymmetricEncryptionAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(Mechanism.SHA256, MGF.SHA256, None),
    ),
    "rsa_oaep_sha384": AsymmetricEncryptionAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS_OAEP,
        mechanism_param=(Mechanism.SHA384, MGF.SHA384, None),
    ),
    "rsa_pkcs1v15": AsymmetricEncryptionAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS,
        mechanism_param=None,
    ),
}

_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)
_SHA384_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3041300d060960864801650304020205000430"
)

DIGEST_SIGNATURE_ALGORITHM_SPECS: dict[str, DigestSignatureAlgorithmSpec] = {
    "rsa_pkcs1v15_sha256": DigestSignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS,
        digest_name="sha256",
        digest_size=32,
        digest_info_prefix=_SHA256_DIGEST_INFO_PREFIX,
    ),
    "rsa_pkcs1v15_sha384": DigestSignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS,
        digest_name="sha384",
        digest_size=48,
        digest_info_prefix=_SHA384_DIGEST_INFO_PREFIX,
    ),
    "rsa_pss_sha256": DigestSignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS_PSS,
        digest_name="sha256",
        digest_size=32,
        mechanism_param=(Mechanism.SHA256, MGF.SHA256, 32),
    ),
    "rsa_pss_sha384": DigestSignatureAlgorithmSpec(
        key_type=KeyType.RSA,
        mechanism=Mechanism.RSA_PKCS_PSS,
        digest_name="sha384",
        digest_size=48,
        mechanism_param=(Mechanism.SHA384, MGF.SHA384, 48),
    ),
    "ecdsa_sha256": DigestSignatureAlgorithmSpec(
        key_type=KeyType.EC,
        mechanism=Mechanism.ECDSA,
        digest_name="sha256",
        digest_size=32,
    ),
    "ecdsa_sha384": DigestSignatureAlgorithmSpec(
        key_type=KeyType.EC,
        mechanism=Mechanism.ECDSA,
        digest_name="sha384",
        digest_size=48,
    ),
}

_SIGNATURE_HASH_ALGORITHMS: dict[str, str] = {
    "rsa_pkcs1v15_sha256": "sha256",
    "rsa_pkcs1v15_sha384": "sha384",
    "rsa_pss_sha256": "sha256",
    "rsa_pss_sha384": "sha384",
    "ecdsa_sha256": "sha256",
    "ecdsa_sha384": "sha384",
}


def _normalize_algorithm_name(algorithm: str) -> str:
    return algorithm.strip().lower().replace("-", "_")


def _resolve_signature_algorithm(algorithm: str) -> SignatureAlgorithmSpec:
    normalized = _normalize_algorithm_name(algorithm)
    spec = SIGNATURE_ALGORITHM_SPECS.get(normalized)
    if spec is None:
        available = ", ".join(sorted(SIGNATURE_ALGORITHM_SPECS.keys()))
        raise ValueError(
            f"Unsupported signing algorithm '{algorithm}'. Available: {available}"
        )
    return spec


def _resolve_asymmetric_encryption_algorithm(
    algorithm: str,
) -> AsymmetricEncryptionAlgorithmSpec:
    normalized = _normalize_algorithm_name(algorithm)
    spec = ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS.get(normalized)
    if spec is None:
        available = ", ".join(sorted(ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS.keys()))
        raise ValueError(
            f"Unsupported asymmetric encryption algorithm '{algorithm}'. Available: {available}"
        )
    return spec


def _resolve_digest_signature_algorithm(algorithm: str) -> DigestSignatureAlgorithmSpec:
    normalized = _normalize_algorithm_name(algorithm)
    spec = DIGEST_SIGNATURE_ALGORITHM_SPECS.get(normalized)
    if spec is None:
        available = ", ".join(sorted(DIGEST_SIGNATURE_ALGORITHM_SPECS.keys()))
        raise ValueError(
            f"Unsupported digest signing algorithm '{algorithm}'. Available: {available}"
        )
    return spec


def _resolve_hash_algorithm_name(algorithm: str) -> str:
    normalized = _normalize_algorithm_name(algorithm)
    resolved = _SIGNATURE_HASH_ALGORITHMS.get(normalized)
    if resolved is None:
        available = ", ".join(sorted(_SIGNATURE_HASH_ALGORITHMS.keys()))
        raise ValueError(
            f"Unsupported signing algorithm '{algorithm}'. Available: {available}"
        )
    return resolved


class Pkcs11HsmClient:
    """
    Thin wrapper around python-pkcs11 for symmetric crypto operations.

    This client intentionally works with key handles, not key bytes.
    """

    def __init__(self, config: HsmConfig) -> None:
        self._config = config
        self._lib = pkcs11.lib(config.module_path)
        self._session: pkcs11.Session | None = None

    def __enter__(self) -> "Pkcs11HsmClient":
        self.open()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    @property
    def session(self) -> pkcs11.Session:
        if self._session is None:
            raise HsmOperationError("Session is not open.")
        return self._session

    def open(self) -> None:
        if self._session is not None:
            _logger.debug("HSM session already open.")
            return

        try:
            if self._config.slot_no is not None:
                _logger.info("Opening HSM session using slot=%s", self._config.slot_no)
                token = self._lib.get_token(slot=self._config.slot_no)
            else:
                _logger.info(
                    "Opening HSM session using token_label=%s", self._config.token_label
                )
                token = self._lib.get_token(token_label=self._config.token_label)

            self._session = token.open(user_pin=self._config.user_pin(), rw=True)
            _logger.info("HSM session opened.")
        except Exception as exc:
            _logger.exception("Failed to open HSM session.")
            raise HsmOperationError(
                f"Failed to open HSM session: {_format_exception(exc)}"
            ) from exc

    def close(self) -> None:
        if self._session is None:
            _logger.debug("HSM session already closed.")
            return
        self._session.close()
        self._session = None
        _logger.info("HSM session closed.")

    def get_aes_key(self, label: str) -> pkcs11.SecretKey | None:
        try:
            key = self.session.get_key(
                label=label,
                object_class=ObjectClass.SECRET_KEY,
                key_type=KeyType.AES,
            )
            _logger.debug("Loaded AES key label=%s", label)
            return key
        except pkcs11.exceptions.NoSuchKey:
            _logger.debug("AES key not found label=%s", label)
            return None
        except Exception as exc:
            _logger.exception("Failed to load AES key label=%s", label)
            raise HsmOperationError(
                f"Failed to get key '{label}': {_format_exception(exc)}"
            ) from exc

    @staticmethod
    def list_key_profiles() -> tuple[str, ...]:
        return list_key_profiles()

    @staticmethod
    def get_key_profile(name: str) -> AsymmetricKeyProfile:
        return get_key_profile(name)

    @staticmethod
    def list_signing_algorithms() -> tuple[str, ...]:
        return tuple(sorted(SIGNATURE_ALGORITHM_SPECS.keys()))

    @staticmethod
    def list_asymmetric_encryption_algorithms() -> tuple[str, ...]:
        return tuple(sorted(ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS.keys()))

    @staticmethod
    def list_digest_signing_algorithms() -> tuple[str, ...]:
        return tuple(sorted(DIGEST_SIGNATURE_ALGORITHM_SPECS.keys()))

    @staticmethod
    def build_profile_rotation_plan(
        profile_name: str,
        base_label: str,
        *,
        current_version: int | None = None,
        version_width: int = 4,
    ) -> KeyRotationPlan:
        return build_rotation_plan(
            profile_name=profile_name,
            base_label=base_label,
            current_version=current_version,
            version_width=version_width,
        )

    def build_profile_rotation_plan_from_token(
        self,
        profile_name: str,
        base_label: str,
        *,
        version_width: int = 4,
    ) -> KeyRotationPlan:
        pattern = re.compile(rf"^{re.escape(base_label)}-v(?P<version>\d+)$")
        current_version: int | None = None
        try:
            for obj in self.session.get_objects({Attribute.CLASS: ObjectClass.PRIVATE_KEY}):
                try:
                    label = obj[Attribute.LABEL]
                except Exception:
                    continue
                if not isinstance(label, str):
                    continue
                match = pattern.fullmatch(label)
                if not match:
                    continue
                version = int(match.group("version"))
                if current_version is None or version > current_version:
                    current_version = version
        except Exception as exc:
            _logger.exception(
                "Failed to derive current key version from token base_label=%s",
                base_label,
            )
            raise HsmOperationError(
                f"Failed to derive key rotation plan for '{base_label}': {_format_exception(exc)}"
            ) from exc

        return self.build_profile_rotation_plan(
            profile_name=profile_name,
            base_label=base_label,
            current_version=current_version,
            version_width=version_width,
        )

    @staticmethod
    def root_ca_operations_enabled() -> bool:
        value = os.environ.get("HSM_ALLOW_ROOT_CA", "")
        return value.strip().lower() in {"1", "true", "yes", "on"}

    @staticmethod
    def operation_role() -> str:
        value = os.environ.get("HSM_OPERATION_ROLE", "any")
        normalized = value.strip().lower()
        aliases = {
            "any": "any",
            "all": "any",
            "ca": "ca",
            "app": "app",
        }
        resolved = aliases.get(normalized)
        if resolved is None:
            raise HsmOperationError(
                "Invalid HSM_OPERATION_ROLE. Use one of: any, ca, app."
            )
        return resolved

    @classmethod
    def _enforce_operation_role(
        cls,
        *,
        required_role: str,
        operation: str,
    ) -> None:
        resolved_required_role = required_role.strip().lower()
        if resolved_required_role not in {"ca", "app"}:
            raise ValueError(f"Unsupported required role: {required_role}")
        active_role = cls.operation_role()
        if active_role in {"any", resolved_required_role}:
            _logger.info(
                "Role policy check passed operation=%s required_role=%s active_role=%s",
                operation,
                resolved_required_role,
                active_role,
            )
            return
        raise HsmOperationError(
            "Role separation policy denied operation "
            f"'{operation}'. Required role '{resolved_required_role}', active role '{active_role}'."
        )

    @classmethod
    def _enforce_root_ca_ceremony(
        cls,
        *,
        operation: str,
        ceremony_reference: str | None,
    ) -> None:
        cls._enforce_operation_role(required_role="ca", operation=operation)
        if not cls.root_ca_operations_enabled():
            raise HsmOperationError(
                "Root CA operation denied by policy. "
                "Set HSM_ALLOW_ROOT_CA=true for an approved offline ceremony."
            )
        if ceremony_reference is None or not ceremony_reference.strip():
            raise HsmOperationError(
                f"Root CA operation '{operation}' requires a non-empty ceremony_reference."
            )
        _logger.info(
            "Root CA ceremony policy check passed operation=%s ceremony_reference=%s",
            operation,
            ceremony_reference,
        )

    @staticmethod
    def _resolve_default_x509_signing_algorithm(
        *,
        private_key: pkcs11.PrivateKey,
        public_key: pkcs11.PublicKey | None = None,
        prefer_ca_profile: bool = False,
    ) -> str:
        key_type = private_key[Attribute.KEY_TYPE]
        ec_params: bytes | None = None
        if key_type == KeyType.EC:
            if public_key is not None:
                try:
                    ec_params = public_key[Attribute.EC_PARAMS]
                except Exception:
                    ec_params = None
            if ec_params is None:
                try:
                    ec_params = private_key[Attribute.EC_PARAMS]
                except Exception:
                    ec_params = None
        return default_x509_signing_algorithm_for_key(
            key_type=key_type,
            ec_params=ec_params,
            prefer_ca_profile=prefer_ca_profile,
        )

    def generate_keypair_for_profile(
        self,
        profile_name: str,
        private_label: str,
        public_label: str | None = None,
        *,
        extractable: bool | None = None,
        key_id: bytes | None = None,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        profile = get_key_profile(profile_name)
        resolved_extractable = (
            profile.extractable if extractable is None else extractable
        )

        if profile.key_type == "RSA":
            if profile.rsa_bits is None:
                raise ValueError(
                    f"Profile '{profile.name}' is RSA but rsa_bits is not configured."
                )
            return self.generate_rsa_keypair(
                private_label=private_label,
                public_label=public_label,
                bits=profile.rsa_bits,
                extractable=resolved_extractable,
                key_id=key_id,
            )
        if profile.key_type == "EC":
            if profile.ec_curve is None:
                raise ValueError(
                    f"Profile '{profile.name}' is EC but ec_curve is not configured."
                )
            return self.generate_ec_keypair(
                private_label=private_label,
                public_label=public_label,
                curve=profile.ec_curve,
                extractable=resolved_extractable,
                key_id=key_id,
            )
        raise ValueError(f"Unsupported profile key type: {profile.key_type}")

    def create_root_ca_key(
        self,
        private_label: str,
        public_label: str | None = None,
        *,
        ceremony_reference: str,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        self._enforce_root_ca_ceremony(
            operation="create_root_ca_key",
            ceremony_reference=ceremony_reference,
        )
        public_key, private_key = self.generate_keypair_for_profile(
            "ca_root",
            private_label=private_label,
            public_label=public_label,
        )
        _logger.info(
            "Root CA key generated private_label=%s public_label=%s",
            private_label,
            public_label or f"{private_label}.pub",
        )
        return public_key, private_key

    def create_intermediate_key(
        self,
        private_label: str,
        public_label: str | None = None,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        self._enforce_operation_role(
            required_role="ca",
            operation="create_intermediate_key",
        )
        public_key, private_key = self.generate_keypair_for_profile(
            "ca_intermediate",
            private_label=private_label,
            public_label=public_label,
        )
        _logger.info(
            "Intermediate CA key generated private_label=%s public_label=%s",
            private_label,
            public_label or f"{private_label}.pub",
        )
        return public_key, private_key

    def create_csr(
        self,
        *,
        private_label: str,
        subject_common_name: str,
        public_label: str | None = None,
        signing_algorithm: str | None = None,
        organization: str | None = None,
        organizational_unit: str | None = None,
        country: str | None = None,
        state_or_province: str | None = None,
        locality: str | None = None,
        is_ca: bool = False,
        ca_path_length: int | None = None,
        mtls_usage: str | None = None,
        dns_names: list[str] | tuple[str, ...] | None = None,
    ) -> bytes:
        if is_ca:
            self._enforce_operation_role(
                required_role="ca",
                operation="create_csr_ca",
            )
        resolved_public_label = public_label or f"{private_label}.pub"
        private_key = self.get_private_key(private_label)
        if private_key is None:
            raise HsmOperationError(
                f"Private key '{private_label}' was not found for CSR creation."
            )
        public_key = self.get_public_key(resolved_public_label)
        if public_key is None:
            raise HsmOperationError(
                f"Public key '{resolved_public_label}' was not found for CSR creation."
            )

        resolved_algorithm = signing_algorithm or self._resolve_default_x509_signing_algorithm(
            private_key=private_key,
            public_key=public_key,
        )
        subject = build_distinguished_name(
            subject_common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state_or_province=state_or_province,
            locality=locality,
        )
        public_key_info = pkcs11_public_key_to_public_key_info(public_key)
        requested_extensions = None
        if is_ca:
            requested_extensions = build_ca_csr_extensions(
                path_length=ca_path_length,
            )
        elif mtls_usage is not None or dns_names:
            requested_extensions = build_leaf_csr_extensions(
                usage=mtls_usage or "server",
                dns_names=dns_names,
            )

        request = create_certificate_signing_request(
            subject=subject,
            subject_public_key_info=public_key_info,
            sign_tbs=lambda payload: self.sign(
                private_key,
                payload,
                algorithm=resolved_algorithm,
            ),
            signing_algorithm=resolved_algorithm,
            extensions=requested_extensions,
        )
        _logger.info(
            "CSR generated private_label=%s subject_cn=%s algorithm=%s is_ca=%s",
            private_label,
            subject_common_name,
            resolved_algorithm,
            is_ca,
        )
        return dump_csr_pem(request)

    def create_root_ca_cert(
        self,
        *,
        root_private_label: str,
        subject_common_name: str,
        root_public_label: str | None = None,
        signing_algorithm: str | None = None,
        organization: str | None = None,
        organizational_unit: str | None = None,
        country: str | None = None,
        state_or_province: str | None = None,
        locality: str | None = None,
        validity_days: int = 3650,
        path_length: int | None = 1,
        ceremony_reference: str,
    ) -> bytes:
        self._enforce_root_ca_ceremony(
            operation="create_root_ca_cert",
            ceremony_reference=ceremony_reference,
        )
        resolved_public_label = root_public_label or f"{root_private_label}.pub"
        private_key = self.get_private_key(root_private_label)
        if private_key is None:
            raise HsmOperationError(
                f"Root private key '{root_private_label}' was not found."
            )
        public_key = self.get_public_key(resolved_public_label)
        if public_key is None:
            raise HsmOperationError(
                f"Root public key '{resolved_public_label}' was not found."
            )

        resolved_algorithm = signing_algorithm or self._resolve_default_x509_signing_algorithm(
            private_key=private_key,
            public_key=public_key,
            prefer_ca_profile=True,
        )
        subject = build_distinguished_name(
            subject_common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state_or_province=state_or_province,
            locality=locality,
        )
        public_key_info = pkcs11_public_key_to_public_key_info(public_key)

        certificate = create_self_signed_ca_certificate(
            subject=subject,
            subject_public_key_info=public_key_info,
            sign_tbs=lambda payload: self.sign(
                private_key,
                payload,
                algorithm=resolved_algorithm,
            ),
            signing_algorithm=resolved_algorithm,
            validity_days=validity_days,
            path_length=path_length,
        )
        _logger.info(
            "Root CA certificate created root_private_label=%s algorithm=%s validity_days=%d",
            root_private_label,
            resolved_algorithm,
            validity_days,
        )
        return dump_certificate_pem(certificate)

    def sign_intermediate_csr(
        self,
        *,
        root_private_label: str,
        root_certificate_pem: bytes | str,
        intermediate_csr_pem: bytes | str,
        root_public_label: str | None = None,
        signing_algorithm: str | None = None,
        validity_days: int = 1825,
        path_length: int | None = 0,
        ceremony_reference: str,
    ) -> bytes:
        self._enforce_root_ca_ceremony(
            operation="sign_intermediate_csr",
            ceremony_reference=ceremony_reference,
        )

        root_private_key = self.get_private_key(root_private_label)
        if root_private_key is None:
            raise HsmOperationError(
                f"Root private key '{root_private_label}' was not found."
            )
        root_public_key = None
        if root_public_label is not None:
            root_public_key = self.get_public_key(root_public_label)
            if root_public_key is None:
                raise HsmOperationError(
                    f"Root public key '{root_public_label}' was not found."
                )

        resolved_algorithm = signing_algorithm or self._resolve_default_x509_signing_algorithm(
            private_key=root_private_key,
            public_key=root_public_key,
            prefer_ca_profile=True,
        )
        issuer_certificate = load_certificate(root_certificate_pem)
        request = load_certificate_signing_request(intermediate_csr_pem)

        certificate = sign_csr_as_ca(
            issuer_certificate=issuer_certificate,
            request=request,
            sign_tbs=lambda payload: self.sign(
                root_private_key,
                payload,
                algorithm=resolved_algorithm,
            ),
            signing_algorithm=resolved_algorithm,
            validity_days=validity_days,
            path_length=path_length,
        )
        _logger.info(
            "Intermediate CSR signed root_private_label=%s algorithm=%s validity_days=%d",
            root_private_label,
            resolved_algorithm,
            validity_days,
        )
        return dump_certificate_pem(certificate)

    @staticmethod
    def _normalize_pem_text(data: bytes | str) -> str:
        if isinstance(data, bytes):
            text = data.decode("utf-8")
        else:
            text = data
        return text.strip() + "\n"

    def generate_mtls_leaf_key_and_csr(
        self,
        *,
        profile_name: str,
        private_label: str,
        subject_common_name: str,
        public_label: str | None = None,
        organization: str | None = None,
        organizational_unit: str | None = None,
        country: str | None = None,
        state_or_province: str | None = None,
        locality: str | None = None,
        signing_algorithm: str | None = None,
        dns_names: list[str] | tuple[str, ...] | None = None,
    ) -> MtlsLeafCsrBundle:
        self._enforce_operation_role(
            required_role="app",
            operation="generate_mtls_leaf_key_and_csr",
        )
        usage_by_profile = {
            "mtls_server": "server",
            "mtls_client": "client",
        }
        usage = usage_by_profile.get(profile_name)
        if usage is None:
            raise ValueError(
                "mTLS leaf profile must be one of: mtls_server, mtls_client."
            )

        resolved_public_label = public_label or f"{private_label}.pub"
        self.generate_keypair_for_profile(
            profile_name=profile_name,
            private_label=private_label,
            public_label=resolved_public_label,
        )
        csr_pem = self.create_csr(
            private_label=private_label,
            public_label=resolved_public_label,
            subject_common_name=subject_common_name,
            organization=organization,
            organizational_unit=organizational_unit,
            country=country,
            state_or_province=state_or_province,
            locality=locality,
            signing_algorithm=signing_algorithm,
            is_ca=False,
            mtls_usage=usage,
            dns_names=dns_names,
        )
        _logger.info(
            "Generated mTLS leaf key and CSR profile=%s private_label=%s public_label=%s",
            profile_name,
            private_label,
            resolved_public_label,
        )
        return MtlsLeafCsrBundle(
            profile_name=profile_name,
            private_key_label=private_label,
            public_key_label=resolved_public_label,
            csr_pem=csr_pem,
        )

    def sign_leaf_csr(
        self,
        *,
        intermediate_private_label: str,
        intermediate_certificate_pem: bytes | str,
        leaf_csr_pem: bytes | str,
        intermediate_public_label: str | None = None,
        signing_algorithm: str | None = None,
        validity_days: int = 397,
        mtls_usage: str = "server",
        dns_names: list[str] | tuple[str, ...] | None = None,
    ) -> bytes:
        self._enforce_operation_role(
            required_role="ca",
            operation="sign_leaf_csr",
        )
        intermediate_private_key = self.get_private_key(intermediate_private_label)
        if intermediate_private_key is None:
            raise HsmOperationError(
                f"Intermediate private key '{intermediate_private_label}' was not found."
            )
        intermediate_public_key = None
        if intermediate_public_label is not None:
            intermediate_public_key = self.get_public_key(intermediate_public_label)
            if intermediate_public_key is None:
                raise HsmOperationError(
                    f"Intermediate public key '{intermediate_public_label}' was not found."
                )

        resolved_algorithm = signing_algorithm or self._resolve_default_x509_signing_algorithm(
            private_key=intermediate_private_key,
            public_key=intermediate_public_key,
            prefer_ca_profile=True,
        )
        issuer_certificate = load_certificate(intermediate_certificate_pem)
        request = load_certificate_signing_request(leaf_csr_pem)
        certificate = sign_csr_as_leaf(
            issuer_certificate=issuer_certificate,
            request=request,
            sign_tbs=lambda payload: self.sign(
                intermediate_private_key,
                payload,
                algorithm=resolved_algorithm,
            ),
            signing_algorithm=resolved_algorithm,
            usage=mtls_usage,
            validity_days=validity_days,
            dns_names=dns_names,
        )
        _logger.info(
            "Leaf CSR signed intermediate_private_label=%s algorithm=%s usage=%s validity_days=%d",
            intermediate_private_label,
            resolved_algorithm,
            mtls_usage,
            validity_days,
        )
        return dump_certificate_pem(certificate)

    def sign_mtls_leaf_csr(
        self,
        *,
        profile_name: str,
        leaf_private_label: str,
        leaf_csr_pem: bytes | str,
        intermediate_private_label: str,
        intermediate_certificate_pem: bytes | str,
        root_certificate_pem: bytes | str | None = None,
        leaf_public_label: str | None = None,
        intermediate_public_label: str | None = None,
        signing_algorithm: str | None = None,
        validity_days: int = 397,
        mtls_usage: str | None = None,
        dns_names: list[str] | tuple[str, ...] | None = None,
    ) -> IssuedMtlsLeaf:
        usage_by_profile = {
            "mtls_server": "server",
            "mtls_client": "client",
        }
        derived_usage = usage_by_profile.get(profile_name)
        usage = mtls_usage or derived_usage
        if usage is None:
            raise ValueError(
                "mTLS leaf profile must be one of: mtls_server, mtls_client."
            )
        resolved_leaf_public_label = leaf_public_label or f"{leaf_private_label}.pub"
        leaf_cert = self.sign_leaf_csr(
            intermediate_private_label=intermediate_private_label,
            intermediate_certificate_pem=intermediate_certificate_pem,
            leaf_csr_pem=leaf_csr_pem,
            intermediate_public_label=intermediate_public_label,
            signing_algorithm=signing_algorithm,
            validity_days=validity_days,
            mtls_usage=usage,
            dns_names=dns_names,
        )
        chain_parts = [
            self._normalize_pem_text(leaf_cert),
            self._normalize_pem_text(intermediate_certificate_pem),
        ]
        if root_certificate_pem is not None:
            chain_parts.append(self._normalize_pem_text(root_certificate_pem))
        chain_pem = "".join(chain_parts).encode("utf-8")
        return IssuedMtlsLeaf(
            profile_name=profile_name,
            private_key_label=leaf_private_label,
            public_key_label=resolved_leaf_public_label,
            csr_pem=leaf_csr_pem.encode("utf-8")
            if isinstance(leaf_csr_pem, str)
            else leaf_csr_pem,
            certificate_pem=leaf_cert,
            certificate_chain_pem=chain_pem,
        )

    def generate_rsa_keypair(
        self,
        private_label: str,
        public_label: str | None = None,
        bits: int = 3072,
        *,
        extractable: bool = False,
        key_id: bytes | None = None,
        allow_sign: bool = True,
        allow_verify: bool = True,
        allow_decrypt: bool = False,
        allow_encrypt: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        if bits not in {2048, 3072, 4096}:
            raise ValueError("RSA key size must be one of: 2048, 3072, 4096.")

        resolved_public_label = public_label or f"{private_label}.pub"
        try:
            public_key, private_key = self.session.generate_keypair(
                KeyType.RSA,
                bits,
                id=key_id,
                store=True,
                public_template={
                    Attribute.LABEL: resolved_public_label,
                    Attribute.TOKEN: True,
                    Attribute.VERIFY: allow_verify,
                    Attribute.ENCRYPT: allow_encrypt,
                },
                private_template={
                    Attribute.LABEL: private_label,
                    Attribute.TOKEN: True,
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: extractable,
                    Attribute.SIGN: allow_sign,
                    Attribute.DECRYPT: allow_decrypt,
                },
            )
            _logger.info(
                "Generated RSA keypair private_label=%s public_label=%s bits=%d extractable=%s",
                private_label,
                resolved_public_label,
                bits,
                extractable,
            )
            return public_key, private_key
        except Exception as exc:
            _logger.exception(
                "Failed to generate RSA keypair private_label=%s public_label=%s",
                private_label,
                resolved_public_label,
            )
            raise HsmOperationError(
                f"Failed to generate RSA keypair '{private_label}': {_format_exception(exc)}"
            ) from exc

    def generate_ec_keypair(
        self,
        private_label: str,
        public_label: str | None = None,
        curve: str = "secp256r1",
        *,
        extractable: bool = False,
        key_id: bytes | None = None,
        allow_sign: bool = True,
        allow_verify: bool = True,
        allow_derive: bool = False,
    ) -> tuple[pkcs11.PublicKey, pkcs11.PrivateKey]:
        resolved_public_label = public_label or f"{private_label}.pub"

        try:
            ec_params = ec_util.encode_named_curve_parameters(curve)
        except Exception as exc:
            raise ValueError(f"Unsupported EC curve '{curve}'.") from exc

        try:
            parameters = self.session.create_domain_parameters(
                KeyType.EC,
                {Attribute.EC_PARAMS: ec_params},
                local=True,
            )
            public_key, private_key = parameters.generate_keypair(
                id=key_id,
                store=True,
                public_template={
                    Attribute.LABEL: resolved_public_label,
                    Attribute.TOKEN: True,
                    Attribute.VERIFY: allow_verify,
                    Attribute.DERIVE: allow_derive,
                },
                private_template={
                    Attribute.LABEL: private_label,
                    Attribute.TOKEN: True,
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: extractable,
                    Attribute.SIGN: allow_sign,
                    Attribute.DERIVE: allow_derive,
                },
            )
            _logger.info(
                "Generated EC keypair private_label=%s public_label=%s curve=%s extractable=%s",
                private_label,
                resolved_public_label,
                curve,
                extractable,
            )
            return public_key, private_key
        except Exception as exc:
            _logger.exception(
                "Failed to generate EC keypair private_label=%s public_label=%s curve=%s",
                private_label,
                resolved_public_label,
                curve,
            )
            raise HsmOperationError(
                f"Failed to generate EC keypair '{private_label}': {_format_exception(exc)}"
            ) from exc

    def get_private_key(
        self, label: str, key_type: KeyType | None = None
    ) -> pkcs11.PrivateKey | None:
        try:
            private_key = self.session.get_key(
                label=label,
                object_class=ObjectClass.PRIVATE_KEY,
                key_type=key_type,
            )
            _logger.debug("Loaded private key label=%s key_type=%s", label, key_type)
            return private_key
        except pkcs11.exceptions.NoSuchKey:
            _logger.debug("Private key not found label=%s key_type=%s", label, key_type)
            return None
        except Exception as exc:
            _logger.exception("Failed to load private key label=%s", label)
            raise HsmOperationError(
                f"Failed to get private key '{label}': {_format_exception(exc)}"
            ) from exc

    def get_public_key(
        self, label: str, key_type: KeyType | None = None
    ) -> pkcs11.PublicKey | None:
        try:
            public_key = self.session.get_key(
                label=label,
                object_class=ObjectClass.PUBLIC_KEY,
                key_type=key_type,
            )
            _logger.debug("Loaded public key label=%s key_type=%s", label, key_type)
            return public_key
        except pkcs11.exceptions.NoSuchKey:
            _logger.debug("Public key not found label=%s key_type=%s", label, key_type)
            return None
        except Exception as exc:
            _logger.exception("Failed to load public key label=%s", label)
            raise HsmOperationError(
                f"Failed to get public key '{label}': {_format_exception(exc)}"
            ) from exc

    def sign(
        self,
        private_key: pkcs11.PrivateKey,
        data: bytes,
        algorithm: str = "rsa_pss_sha256",
    ) -> bytes:
        spec = _resolve_signature_algorithm(algorithm)
        try:
            actual_key_type = private_key[Attribute.KEY_TYPE]
            if actual_key_type != spec.key_type:
                raise ValueError(
                    f"Algorithm '{algorithm}' requires key type {spec.key_type.name}, "
                    f"but key type is {actual_key_type}."
                )
        except (KeyError, TypeError):
            # Some providers may not expose KEY_TYPE for loaded objects.
            pass
        try:
            signature = private_key.sign(
                data,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
            _logger.info(
                "Signed payload using algorithm=%s signature_size=%d",
                _normalize_algorithm_name(algorithm),
                len(signature),
            )
            return signature
        except Exception as exc:
            _logger.exception("Signing failed algorithm=%s", algorithm)
            raise HsmOperationError(
                f"Signing failed for algorithm '{algorithm}': {_format_exception(exc)}"
            ) from exc

    def verify(
        self,
        public_key: pkcs11.PublicKey,
        data: bytes,
        signature: bytes,
        algorithm: str = "rsa_pss_sha256",
    ) -> bool:
        spec = _resolve_signature_algorithm(algorithm)
        try:
            actual_key_type = public_key[Attribute.KEY_TYPE]
            if actual_key_type != spec.key_type:
                raise ValueError(
                    f"Algorithm '{algorithm}' requires key type {spec.key_type.name}, "
                    f"but key type is {actual_key_type}."
                )
        except (KeyError, TypeError):
            # Some providers may not expose KEY_TYPE for loaded objects.
            pass
        try:
            verified = public_key.verify(
                data,
                signature,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
            _logger.info(
                "Verified signature using algorithm=%s result=%s",
                _normalize_algorithm_name(algorithm),
                verified,
            )
            return bool(verified)
        except pkcs11.exceptions.SignatureInvalid:
            _logger.warning(
                "Signature verification failed (invalid signature) algorithm=%s",
                _normalize_algorithm_name(algorithm),
            )
            return False
        except Exception as exc:
            _logger.exception("Signature verification failed algorithm=%s", algorithm)
            raise HsmOperationError(
                f"Verification failed for algorithm '{algorithm}': {_format_exception(exc)}"
            ) from exc

    @staticmethod
    def _prepare_digest_payload(
        *,
        spec: DigestSignatureAlgorithmSpec,
        digest: bytes,
    ) -> bytes:
        if len(digest) != spec.digest_size:
            raise ValueError(
                f"Digest length mismatch for {spec.digest_name}: "
                f"expected {spec.digest_size} bytes, got {len(digest)}."
            )
        if spec.digest_info_prefix is not None:
            return spec.digest_info_prefix + digest
        return digest

    def sign_blob(
        self,
        *,
        private_label: str,
        blob: bytes,
        algorithm: str = "rsa_pss_sha256",
    ) -> DetachedSignature:
        self._enforce_operation_role(required_role="app", operation="sign_blob")
        private_key = self.get_private_key(private_label)
        if private_key is None:
            raise HsmOperationError(f"Private key '{private_label}' was not found.")
        signature = self.sign(
            private_key,
            blob,
            algorithm=algorithm,
        )
        resolved_algorithm = _normalize_algorithm_name(algorithm)
        detached = DetachedSignature(
            algorithm=resolved_algorithm,
            hash_algorithm=_resolve_hash_algorithm_name(resolved_algorithm),
            key_label=private_label,
            input_type="blob",
            signature=signature,
        )
        _logger.info(
            "sign_blob complete key_label=%s algorithm=%s signature_size=%d",
            private_label,
            resolved_algorithm,
            len(signature),
        )
        return detached

    def verify_blob(
        self,
        *,
        public_label: str,
        blob: bytes,
        detached_signature: DetachedSignature,
    ) -> bool:
        self._enforce_operation_role(required_role="app", operation="verify_blob")
        if detached_signature.input_type != "blob":
            raise ValueError(
                "Detached signature input_type mismatch; expected 'blob'."
            )
        public_key = self.get_public_key(public_label)
        if public_key is None:
            raise HsmOperationError(f"Public key '{public_label}' was not found.")
        verified = self.verify(
            public_key,
            blob,
            detached_signature.signature,
            algorithm=detached_signature.algorithm,
        )
        _logger.info(
            "verify_blob result=%s key_label=%s algorithm=%s",
            verified,
            public_label,
            detached_signature.algorithm,
        )
        return verified

    def sign_digest(
        self,
        *,
        private_label: str,
        digest: bytes,
        algorithm: str = "rsa_pss_sha256",
    ) -> DetachedSignature:
        self._enforce_operation_role(required_role="app", operation="sign_digest")
        spec = _resolve_digest_signature_algorithm(algorithm)
        private_key = self.get_private_key(private_label, key_type=spec.key_type)
        if private_key is None:
            raise HsmOperationError(
                f"Private key '{private_label}' was not found for {spec.key_type.name}."
            )
        payload = self._prepare_digest_payload(spec=spec, digest=digest)
        try:
            signature = private_key.sign(
                payload,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
        except Exception as exc:
            _logger.exception(
                "sign_digest failed key_label=%s algorithm=%s",
                private_label,
                _normalize_algorithm_name(algorithm),
            )
            raise HsmOperationError(
                f"Digest signing failed for algorithm '{algorithm}': {_format_exception(exc)}"
            ) from exc

        resolved_algorithm = _normalize_algorithm_name(algorithm)
        detached = DetachedSignature(
            algorithm=resolved_algorithm,
            hash_algorithm=spec.digest_name,
            key_label=private_label,
            input_type="digest",
            signature=signature,
        )
        _logger.info(
            "sign_digest complete key_label=%s algorithm=%s signature_size=%d",
            private_label,
            resolved_algorithm,
            len(signature),
        )
        return detached

    def verify_digest(
        self,
        *,
        public_label: str,
        digest: bytes,
        detached_signature: DetachedSignature,
    ) -> bool:
        self._enforce_operation_role(required_role="app", operation="verify_digest")
        if detached_signature.input_type != "digest":
            raise ValueError(
                "Detached signature input_type mismatch; expected 'digest'."
            )
        spec = _resolve_digest_signature_algorithm(detached_signature.algorithm)
        public_key = self.get_public_key(public_label, key_type=spec.key_type)
        if public_key is None:
            raise HsmOperationError(
                f"Public key '{public_label}' was not found for {spec.key_type.name}."
            )
        payload = self._prepare_digest_payload(spec=spec, digest=digest)
        try:
            verified = public_key.verify(
                payload,
                detached_signature.signature,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
            _logger.info(
                "verify_digest result=%s key_label=%s algorithm=%s",
                bool(verified),
                public_label,
                detached_signature.algorithm,
            )
            return bool(verified)
        except pkcs11.exceptions.SignatureInvalid:
            _logger.warning(
                "verify_digest invalid signature key_label=%s algorithm=%s",
                public_label,
                detached_signature.algorithm,
            )
            return False
        except Exception as exc:
            _logger.exception(
                "verify_digest failed key_label=%s algorithm=%s",
                public_label,
                detached_signature.algorithm,
            )
            raise HsmOperationError(
                f"Digest verification failed for algorithm '{detached_signature.algorithm}': {_format_exception(exc)}"
            ) from exc

    def encrypt_confidential(
        self,
        public_key: pkcs11.PublicKey,
        plaintext: bytes,
        algorithm: str = "rsa_oaep_sha256",
    ) -> bytes:
        """
        Encrypt data for confidentiality using an asymmetric public key.

        This is separate from signing and should be paired with decrypt_confidential().
        """
        spec = _resolve_asymmetric_encryption_algorithm(algorithm)
        try:
            actual_key_type = public_key[Attribute.KEY_TYPE]
            if actual_key_type != spec.key_type:
                raise ValueError(
                    f"Algorithm '{algorithm}' requires key type {spec.key_type.name}, "
                    f"but key type is {actual_key_type}."
                )
        except (KeyError, TypeError):
            pass

        try:
            ciphertext = public_key.encrypt(
                plaintext,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
            _logger.info(
                "Asymmetric encryption complete algorithm=%s plaintext_size=%d ciphertext_size=%d",
                _normalize_algorithm_name(algorithm),
                len(plaintext),
                len(ciphertext),
            )
            return ciphertext
        except Exception as exc:
            _logger.exception("Asymmetric encryption failed algorithm=%s", algorithm)
            raise HsmOperationError(
                f"Asymmetric encryption failed for algorithm '{algorithm}': {_format_exception(exc)}"
            ) from exc

    def decrypt_confidential(
        self,
        private_key: pkcs11.PrivateKey,
        ciphertext: bytes,
        algorithm: str = "rsa_oaep_sha256",
    ) -> bytes:
        """Decrypt ciphertext produced by encrypt_confidential()."""
        spec = _resolve_asymmetric_encryption_algorithm(algorithm)
        try:
            actual_key_type = private_key[Attribute.KEY_TYPE]
            if actual_key_type != spec.key_type:
                raise ValueError(
                    f"Algorithm '{algorithm}' requires key type {spec.key_type.name}, "
                    f"but key type is {actual_key_type}."
                )
        except (KeyError, TypeError):
            pass

        try:
            plaintext = private_key.decrypt(
                ciphertext,
                mechanism=spec.mechanism,
                mechanism_param=spec.mechanism_param,
            )
            _logger.info(
                "Asymmetric decryption complete algorithm=%s ciphertext_size=%d plaintext_size=%d",
                _normalize_algorithm_name(algorithm),
                len(ciphertext),
                len(plaintext),
            )
            return plaintext
        except Exception as exc:
            _logger.exception("Asymmetric decryption failed algorithm=%s", algorithm)
            raise HsmOperationError(
                f"Asymmetric decryption failed for algorithm '{algorithm}': {_format_exception(exc)}"
            ) from exc

    def generate_aes_key(
        self,
        label: str,
        bits: int = 256,
        *,
        extractable: bool = False,
        allow_encrypt: bool = True,
        allow_decrypt: bool = True,
        allow_wrap: bool = False,
        allow_unwrap: bool = False,
    ) -> pkcs11.SecretKey:
        if bits not in {128, 192, 256}:
            raise ValueError("AES key size must be 128, 192, or 256 bits.")
        try:
            key = self.session.generate_key(
                KeyType.AES,
                bits,
                store=True,
                template={
                    Attribute.LABEL: label,
                    Attribute.TOKEN: True,
                    Attribute.ENCRYPT: allow_encrypt,
                    Attribute.DECRYPT: allow_decrypt,
                    Attribute.WRAP: allow_wrap,
                    Attribute.UNWRAP: allow_unwrap,
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: extractable,
                },
            )
            _logger.info(
                "Generated AES key label=%s bits=%d extractable=%s encrypt=%s decrypt=%s wrap=%s unwrap=%s",
                label,
                bits,
                extractable,
                allow_encrypt,
                allow_decrypt,
                allow_wrap,
                allow_unwrap,
            )
            return key
        except Exception as exc:
            _logger.exception("Failed to generate AES key label=%s", label)
            raise HsmOperationError(
                f"Failed to generate key '{label}': {_format_exception(exc)}"
            ) from exc

    def generate_aes_kek(
        self,
        label: str,
        bits: int = 256,
        *,
        extractable: bool = False,
    ) -> pkcs11.SecretKey:
        """
        Generate an AES key-encryption-key (KEK) for wrap/unwrap operations.
        """
        return self.generate_aes_key(
            label=label,
            bits=bits,
            extractable=extractable,
            allow_encrypt=False,
            allow_decrypt=False,
            allow_wrap=True,
            allow_unwrap=True,
        )

    @staticmethod
    def format_versioned_label(base_label: str, version: int, width: int = 4) -> str:
        """Format `<base>-vNNNN` versioned label."""
        if version < 1:
            raise ValueError("Key version must be >= 1.")
        if width < 1:
            raise ValueError("Label width must be >= 1.")
        return f"{base_label}-v{version:0{width}d}"

    def list_aes_key_versions(self, base_label: str) -> list[VersionedAesKey]:
        """List versioned AES keys matching `<base_label>-vNNNN`."""
        pattern = re.compile(rf"^{re.escape(base_label)}-v(?P<version>\d+)$")
        versions: list[VersionedAesKey] = []

        try:
            objects = self.session.get_objects(
                {
                    Attribute.CLASS: ObjectClass.SECRET_KEY,
                    Attribute.KEY_TYPE: KeyType.AES,
                }
            )
            for obj in objects:
                try:
                    label = obj[Attribute.LABEL]
                except Exception:
                    continue
                if not isinstance(label, str):
                    continue
                match = pattern.fullmatch(label)
                if not match:
                    continue
                versions.append(
                    VersionedAesKey(
                        base_label=base_label,
                        version=int(match.group("version")),
                        label=label,
                    )
                )
        except Exception as exc:
            _logger.exception("Failed listing versioned keys base_label=%s", base_label)
            raise HsmOperationError(
                f"Failed to list AES key versions for '{base_label}': {_format_exception(exc)}"
            ) from exc

        versions.sort(key=lambda item: item.version)
        _logger.debug(
            "Found %d versioned AES keys for base_label=%s", len(versions), base_label
        )
        return versions

    def get_latest_aes_key(
        self, base_label: str
    ) -> tuple[VersionedAesKey, pkcs11.SecretKey] | None:
        """Get the highest-version AES key for a base label."""
        versions = self.list_aes_key_versions(base_label)
        if not versions:
            _logger.debug("No versioned keys exist for base_label=%s", base_label)
            return None

        latest = versions[-1]
        key = self.get_aes_key(latest.label)
        if key is None:
            raise HsmOperationError(
                f"Latest key label '{latest.label}' was listed but could not be loaded."
            )
        return latest, key

    def rotate_aes_key(
        self,
        base_label: str,
        bits: int = 256,
        *,
        version_width: int = 4,
        extractable: bool = False,
    ) -> tuple[VersionedAesKey, pkcs11.SecretKey]:
        """
        Create the next versioned AES key for `base_label`.

        Label format is `<base_label>-vNNNN`.
        """
        versions = self.list_aes_key_versions(base_label)
        next_version = versions[-1].version + 1 if versions else 1
        label = self.format_versioned_label(base_label, next_version, width=version_width)
        key = self.generate_aes_key(label=label, bits=bits, extractable=extractable)
        _logger.info(
            "Rotated AES key base_label=%s new_label=%s version=%d",
            base_label,
            label,
            next_version,
        )
        return VersionedAesKey(base_label=base_label, version=next_version, label=label), key

    def wrap_aes_key(
        self,
        wrapping_key: pkcs11.SecretKey,
        target_key: pkcs11.SecretKey,
        *,
        mechanism: Mechanism = Mechanism.AES_KEY_WRAP_PAD,
    ) -> bytes:
        """
        Wrap an AES key with a KEK.

        Note: many PKCS#11 providers require the target key to be extractable.
        """
        try:
            wrapped = wrapping_key.wrap_key(target_key, mechanism=mechanism)
            _logger.info(
                "Wrapped AES key using mechanism=%s wrapped_size=%d",
                mechanism.name if hasattr(mechanism, "name") else mechanism,
                len(wrapped),
            )
            return wrapped
        except Exception as exc:
            _logger.exception("Failed to wrap AES key.")
            raise HsmOperationError(
                f"Failed to wrap key: {_format_exception(exc)}"
            ) from exc

    def unwrap_aes_key(
        self,
        wrapping_key: pkcs11.SecretKey,
        wrapped_key: bytes,
        label: str,
        *,
        extractable: bool = False,
        mechanism: Mechanism = Mechanism.AES_KEY_WRAP_PAD,
    ) -> pkcs11.SecretKey:
        """Unwrap an AES key with a KEK and store it on token."""
        try:
            key = wrapping_key.unwrap_key(
                ObjectClass.SECRET_KEY,
                KeyType.AES,
                wrapped_key,
                label=label,
                mechanism=mechanism,
                store=True,
                template={
                    Attribute.TOKEN: True,
                    Attribute.ENCRYPT: True,
                    Attribute.DECRYPT: True,
                    Attribute.SENSITIVE: True,
                    Attribute.EXTRACTABLE: extractable,
                },
            )
            _logger.info(
                "Unwrapped AES key label=%s mechanism=%s extractable=%s",
                label,
                mechanism.name if hasattr(mechanism, "name") else mechanism,
                extractable,
            )
            return key
        except Exception as exc:
            _logger.exception("Failed to unwrap AES key label=%s", label)
            raise HsmOperationError(
                f"Failed to unwrap key '{label}': {_format_exception(exc)}"
            ) from exc

    def encrypt_aes_gcm(
        self,
        key: pkcs11.SecretKey,
        plaintext: bytes,
        aad: bytes | None = None,
        tag_bits: int = 128,
    ) -> tuple[bytes, bytes]:
        """
        Encrypt using AES-GCM.

        Returns (nonce, ciphertext_with_tag).
        """
        if tag_bits % 8 != 0 or not 32 <= tag_bits <= 128:
            raise ValueError("AES-GCM tag_bits must be a multiple of 8 between 32 and 128.")

        nonce = secrets.token_bytes(12)
        try:
            params = pkcs11.GCMParams(nonce=nonce, aad=aad, tag_bits=tag_bits)
            ciphertext = key.encrypt(
                plaintext,
                mechanism=Mechanism.AES_GCM,
                mechanism_param=params,
            )
            _logger.debug(
                "AES-GCM encryption complete plaintext_size=%d ciphertext_size=%d",
                len(plaintext),
                len(ciphertext),
            )
            return nonce, ciphertext
        except Exception as exc:
            _logger.exception("AES-GCM encryption failed.")
            raise HsmOperationError(
                f"AES-GCM encryption failed: {_format_exception(exc)}"
            ) from exc

    def decrypt_aes_gcm(
        self,
        key: pkcs11.SecretKey,
        nonce: bytes,
        ciphertext: bytes,
        aad: bytes | None = None,
        tag_bits: int = 128,
    ) -> bytes:
        if len(nonce) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes.")
        if tag_bits % 8 != 0 or not 32 <= tag_bits <= 128:
            raise ValueError("AES-GCM tag_bits must be a multiple of 8 between 32 and 128.")

        try:
            params = pkcs11.GCMParams(nonce=nonce, aad=aad, tag_bits=tag_bits)
            plaintext = key.decrypt(
                ciphertext,
                mechanism=Mechanism.AES_GCM,
                mechanism_param=params,
            )
            _logger.debug(
                "AES-GCM decryption complete ciphertext_size=%d plaintext_size=%d",
                len(ciphertext),
                len(plaintext),
            )
            return plaintext
        except Exception as exc:
            _logger.exception("AES-GCM decryption failed.")
            raise HsmOperationError(
                f"AES-GCM decryption failed: {_format_exception(exc)}"
            ) from exc

    def encrypt_aes_cbc(self, key: pkcs11.SecretKey, plaintext: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt using AES-CBC-PAD.

        Returns (iv, ciphertext).
        """
        iv = secrets.token_bytes(16)
        try:
            ciphertext = key.encrypt(
                plaintext,
                mechanism=Mechanism.AES_CBC_PAD,
                mechanism_param=iv,
            )
            _logger.debug(
                "AES-CBC encryption complete plaintext_size=%d ciphertext_size=%d",
                len(plaintext),
                len(ciphertext),
            )
            return iv, ciphertext
        except Exception as exc:
            _logger.exception("AES-CBC encryption failed.")
            raise HsmOperationError(
                f"Encryption failed: {_format_exception(exc)}"
            ) from exc

    def decrypt_aes_cbc(self, key: pkcs11.SecretKey, iv: bytes, ciphertext: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("AES-CBC IV must be 16 bytes.")
        try:
            plaintext = key.decrypt(
                ciphertext,
                mechanism=Mechanism.AES_CBC_PAD,
                mechanism_param=iv,
            )
            _logger.debug(
                "AES-CBC decryption complete ciphertext_size=%d plaintext_size=%d",
                len(ciphertext),
                len(plaintext),
            )
            return plaintext
        except Exception as exc:
            _logger.exception("AES-CBC decryption failed.")
            raise HsmOperationError(
                f"Decryption failed: {_format_exception(exc)}"
            ) from exc

    def encrypt_aes(
        self,
        key: pkcs11.SecretKey,
        plaintext: bytes,
        aad: bytes | None = None,
        prefer_gcm: bool = True,
    ) -> AesCiphertext:
        """
        Encrypt with AES-GCM when available, otherwise fallback to AES-CBC-PAD.

        If fallback occurs, AAD is not supported and must be None.
        """
        if prefer_gcm:
            try:
                nonce, ciphertext = self.encrypt_aes_gcm(key, plaintext, aad=aad, tag_bits=128)
                return AesCiphertext(
                    mechanism="AES_GCM",
                    iv_or_nonce=nonce,
                    ciphertext=ciphertext,
                    aad=aad,
                    tag_bits=128,
                )
            except HsmOperationError as exc:
                if isinstance(exc.__cause__, _GCM_FALLBACK_EXCEPTIONS):
                    _logger.warning("AES-GCM unavailable, falling back to AES-CBC-PAD.")
                    if aad is not None:
                        raise HsmOperationError(
                            "AES-GCM is unavailable and AES-CBC fallback does not support AAD."
                        ) from exc
                else:
                    raise

        iv, ciphertext = self.encrypt_aes_cbc(key, plaintext)
        return AesCiphertext(
            mechanism="AES_CBC_PAD",
            iv_or_nonce=iv,
            ciphertext=ciphertext,
        )

    def decrypt_aes(self, key: pkcs11.SecretKey, payload: AesCiphertext) -> bytes:
        """Decrypt payload returned by encrypt_aes()."""
        if payload.mechanism == "AES_GCM":
            tag_bits = payload.tag_bits if payload.tag_bits is not None else 128
            return self.decrypt_aes_gcm(
                key,
                nonce=payload.iv_or_nonce,
                ciphertext=payload.ciphertext,
                aad=payload.aad,
                tag_bits=tag_bits,
            )
        if payload.mechanism == "AES_CBC_PAD":
            return self.decrypt_aes_cbc(
                key,
                iv=payload.iv_or_nonce,
                ciphertext=payload.ciphertext,
            )
        raise HsmOperationError(f"Unsupported payload mechanism: {payload.mechanism}")
