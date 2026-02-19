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
    owner_role: Literal["ca", "app"] = "app"
    rotation_interval_days: int = 365
    rotation_overlap_days: int = 30
    rotation_notes: str = ""


@dataclass(frozen=True)
class KeyRotationPlan:
    """Scaffolded rotation policy plan for a key profile."""

    profile_name: str
    owner_role: Literal["ca", "app"]
    base_label: str
    current_version: int | None
    next_version: int
    next_label: str
    recommended_interval_days: int
    overlap_days: int
    notes: str


def format_versioned_label(base_label: str, version: int, width: int = 4) -> str:
    if version < 1:
        raise ValueError("version must be >= 1.")
    if width < 1:
        raise ValueError("width must be >= 1.")
    return f"{base_label}-v{version:0{width}d}"


ASYMMETRIC_KEY_PROFILES: dict[str, AsymmetricKeyProfile] = {
    "ca_root": AsymmetricKeyProfile(
        name="ca_root",
        key_type="EC",
        ec_curve="secp384r1",
        default_signing_algorithm="ecdsa_sha384",
        allowed_signing_algorithms=("ecdsa_sha384",),
        extractable=False,
        owner_role="ca",
        rotation_interval_days=3650,
        rotation_overlap_days=90,
        rotation_notes="Root CA rotations should follow an offline ceremony with dual control.",
    ),
    "ca_intermediate": AsymmetricKeyProfile(
        name="ca_intermediate",
        key_type="EC",
        ec_curve="secp384r1",
        default_signing_algorithm="ecdsa_sha384",
        allowed_signing_algorithms=("ecdsa_sha384",),
        extractable=False,
        owner_role="ca",
        rotation_interval_days=1825,
        rotation_overlap_days=90,
        rotation_notes="Rotate intermediates before expiry and overlap old/new chains.",
    ),
    "mtls_server": AsymmetricKeyProfile(
        name="mtls_server",
        key_type="EC",
        ec_curve="secp256r1",
        default_signing_algorithm="ecdsa_sha256",
        allowed_signing_algorithms=("ecdsa_sha256",),
        extractable=False,
        owner_role="app",
        rotation_interval_days=397,
        rotation_overlap_days=30,
        rotation_notes="Use short-lived leaf certificates and automated renewal.",
    ),
    "mtls_client": AsymmetricKeyProfile(
        name="mtls_client",
        key_type="EC",
        ec_curve="secp256r1",
        default_signing_algorithm="ecdsa_sha256",
        allowed_signing_algorithms=("ecdsa_sha256",),
        extractable=False,
        owner_role="app",
        rotation_interval_days=397,
        rotation_overlap_days=30,
        rotation_notes="Use short-lived leaf certificates and automated renewal.",
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
        owner_role="app",
        rotation_interval_days=365,
        rotation_overlap_days=30,
        rotation_notes="Rotate application signing keys annually or on compromise events.",
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


def build_rotation_plan(
    *,
    profile_name: str,
    base_label: str,
    current_version: int | None = None,
    version_width: int = 4,
) -> KeyRotationPlan:
    profile = get_key_profile(profile_name)
    next_version = (current_version or 0) + 1
    return KeyRotationPlan(
        profile_name=profile.name,
        owner_role=profile.owner_role,
        base_label=base_label,
        current_version=current_version,
        next_version=next_version,
        next_label=format_versioned_label(base_label, next_version, width=version_width),
        recommended_interval_days=profile.rotation_interval_days,
        overlap_days=profile.rotation_overlap_days,
        notes=profile.rotation_notes,
    )
