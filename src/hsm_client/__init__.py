"""PKCS#11-backed HSM client package."""

from .asymmetric_profiles import (
    ASYMMETRIC_KEY_PROFILES,
    AsymmetricKeyProfile,
    KeyRotationPlan,
    build_rotation_plan,
    format_versioned_label,
    get_key_profile,
    list_key_profiles,
)
from .config import HsmConfig
from .exceptions import HsmClientError, HsmConfigurationError, HsmOperationError
from .logging_utils import configure_logging
from .pkcs11_client import (
    ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS,
    SIGNATURE_ALGORITHM_SPECS,
    AesCiphertext,
    AsymmetricEncryptionAlgorithmSpec,
    DetachedSignature,
    DigestSignatureAlgorithmSpec,
    IssuedMtlsLeaf,
    MtlsLeafCsrBundle,
    Pkcs11HsmClient,
    SignatureAlgorithmSpec,
    VersionedAesKey,
)
from .x509_ops import DistinguishedName

__all__ = [
    "ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS",
    "ASYMMETRIC_KEY_PROFILES",
    "SIGNATURE_ALGORITHM_SPECS",
    "AesCiphertext",
    "AsymmetricEncryptionAlgorithmSpec",
    "AsymmetricKeyProfile",
    "DetachedSignature",
    "DigestSignatureAlgorithmSpec",
    "DistinguishedName",
    "HsmConfig",
    "HsmClientError",
    "HsmConfigurationError",
    "HsmOperationError",
    "IssuedMtlsLeaf",
    "KeyRotationPlan",
    "MtlsLeafCsrBundle",
    "Pkcs11HsmClient",
    "SignatureAlgorithmSpec",
    "VersionedAesKey",
    "build_rotation_plan",
    "configure_logging",
    "format_versioned_label",
    "get_key_profile",
    "list_key_profiles",
]
