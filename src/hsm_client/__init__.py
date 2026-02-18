"""PKCS#11-backed HSM client package."""

from .asymmetric_profiles import (
    ASYMMETRIC_KEY_PROFILES,
    AsymmetricKeyProfile,
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
    Pkcs11HsmClient,
    SignatureAlgorithmSpec,
    VersionedAesKey,
)

__all__ = [
    "ASYMMETRIC_ENCRYPTION_ALGORITHM_SPECS",
    "ASYMMETRIC_KEY_PROFILES",
    "SIGNATURE_ALGORITHM_SPECS",
    "AesCiphertext",
    "AsymmetricEncryptionAlgorithmSpec",
    "AsymmetricKeyProfile",
    "HsmConfig",
    "HsmClientError",
    "HsmConfigurationError",
    "HsmOperationError",
    "Pkcs11HsmClient",
    "SignatureAlgorithmSpec",
    "VersionedAesKey",
    "configure_logging",
    "get_key_profile",
    "list_key_profiles",
]
