from __future__ import annotations

import logging
import re
import secrets
from dataclasses import dataclass
from typing import Any

import pkcs11
import pkcs11.util.ec as ec_util
from pkcs11 import Attribute, KeyType, Mechanism, MGF, ObjectClass

from .asymmetric_profiles import AsymmetricKeyProfile, get_key_profile, list_key_profiles
from .config import HsmConfig
from .exceptions import HsmOperationError


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
