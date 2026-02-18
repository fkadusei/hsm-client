from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class AsymmetricKeyProfile:
    """
    Opinionated asymmetric key profiles for CA, mTLS, and signing use cases.
    """

    name: str
    key_type: Literal["RSA", "EC"]
    rsa_bits: int | None = None
    ec_curve: str | None = None
    default_signing_algorithm: str = ""
    allowed_signing_algorithms: tuple[str, ...] = ()
    extractable: bool = False


ASYMMETRIC_KEY_PROFILES: dict[str, AsymmetricKeyProfile] = {
    "ca_root": AsymmetricKeyProfile(
        name="ca_root",
        key_type="EC",
        ec_curve="secp384r1",
        default_signing_algorithm="ecdsa_sha384",
        allowed_signing_algorithms=("ecdsa_sha384",),
        extractable=False,
    ),
    "ca_intermediate": AsymmetricKeyProfile(
        name="ca_intermediate",
        key_type="EC",
        ec_curve="secp384r1",
        default_signing_algorithm="ecdsa_sha384",
        allowed_signing_algorithms=("ecdsa_sha384",),
        extractable=False,
    ),
    "mtls_server": AsymmetricKeyProfile(
        name="mtls_server",
        key_type="EC",
        ec_curve="secp256r1",
        default_signing_algorithm="ecdsa_sha256",
        allowed_signing_algorithms=("ecdsa_sha256",),
        extractable=False,
    ),
    "mtls_client": AsymmetricKeyProfile(
        name="mtls_client",
        key_type="EC",
        ec_curve="secp256r1",
        default_signing_algorithm="ecdsa_sha256",
        allowed_signing_algorithms=("ecdsa_sha256",),
        extractable=False,
    ),
    "signing": AsymmetricKeyProfile(
        name="signing",
        key_type="RSA",
        rsa_bits=3072,
        default_signing_algorithm="rsa_pss_sha256",
        allowed_signing_algorithms=(
            "rsa_pss_sha256",
            "rsa_pss_sha384",
            "rsa_pkcs1v15_sha256",
            "rsa_pkcs1v15_sha384",
        ),
        extractable=False,
    ),
}


def list_key_profiles() -> tuple[str, ...]:
    return tuple(sorted(ASYMMETRIC_KEY_PROFILES.keys()))


def get_key_profile(name: str) -> AsymmetricKeyProfile:
    try:
        return ASYMMETRIC_KEY_PROFILES[name]
    except KeyError as exc:
        available = ", ".join(list_key_profiles())
        raise ValueError(
            f"Unknown key profile '{name}'. Available profiles: {available}"
        ) from exc
