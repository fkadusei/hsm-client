from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any

import pkcs11
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

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
            return

        try:
            if self._config.slot_no is not None:
                token = self._lib.get_token(slot=self._config.slot_no)
            else:
                token = self._lib.get_token(token_label=self._config.token_label)

            self._session = token.open(user_pin=self._config.user_pin(), rw=True)
        except Exception as exc:
            raise HsmOperationError(
                f"Failed to open HSM session: {_format_exception(exc)}"
            ) from exc

    def close(self) -> None:
        if self._session is None:
            return
        self._session.close()
        self._session = None

    def get_aes_key(self, label: str) -> pkcs11.SecretKey | None:
        try:
            return self.session.get_key(
                label=label,
                object_class=ObjectClass.SECRET_KEY,
                key_type=KeyType.AES,
            )
        except pkcs11.exceptions.NoSuchKey:
            return None
        except Exception as exc:
            raise HsmOperationError(
                f"Failed to get key '{label}': {_format_exception(exc)}"
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
            return self.session.generate_key(
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
        except Exception as exc:
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
            raise HsmOperationError(
                f"Failed to list AES key versions for '{base_label}': {_format_exception(exc)}"
            ) from exc

        versions.sort(key=lambda item: item.version)
        return versions

    def get_latest_aes_key(
        self, base_label: str
    ) -> tuple[VersionedAesKey, pkcs11.SecretKey] | None:
        """Get the highest-version AES key for a base label."""
        versions = self.list_aes_key_versions(base_label)
        if not versions:
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
            return wrapping_key.wrap_key(target_key, mechanism=mechanism)
        except Exception as exc:
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
            return wrapping_key.unwrap_key(
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
        except Exception as exc:
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
            return nonce, ciphertext
        except Exception as exc:
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
            return key.decrypt(
                ciphertext,
                mechanism=Mechanism.AES_GCM,
                mechanism_param=params,
            )
        except Exception as exc:
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
            return iv, ciphertext
        except Exception as exc:
            raise HsmOperationError(
                f"Encryption failed: {_format_exception(exc)}"
            ) from exc

    def decrypt_aes_cbc(self, key: pkcs11.SecretKey, iv: bytes, ciphertext: bytes) -> bytes:
        if len(iv) != 16:
            raise ValueError("AES-CBC IV must be 16 bytes.")
        try:
            return key.decrypt(
                ciphertext,
                mechanism=Mechanism.AES_CBC_PAD,
                mechanism_param=iv,
            )
        except Exception as exc:
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
