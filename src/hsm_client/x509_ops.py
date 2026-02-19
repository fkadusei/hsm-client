from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable

import pkcs11
from asn1crypto import algos, core, csr, keys, pem, x509
from pkcs11 import Attribute, KeyType


@dataclass(frozen=True)
class DistinguishedName:
    """
    Distinguished Name values used in CSRs and certificates.
    """

    common_name: str
    organization: str | None = None
    organizational_unit: str | None = None
    country: str | None = None
    state_or_province: str | None = None
    locality: str | None = None

    def to_asn1(self) -> x509.Name:
        if not self.common_name.strip():
            raise ValueError("common_name is required for DistinguishedName.")
        if self.country is not None and len(self.country.strip()) != 2:
            raise ValueError("country must be a 2-letter ISO country code.")

        fields: dict[str, str] = {"common_name": self.common_name.strip()}
        if self.organization:
            fields["organization_name"] = self.organization.strip()
        if self.organizational_unit:
            fields["organizational_unit_name"] = self.organizational_unit.strip()
        if self.country:
            fields["country_name"] = self.country.strip().upper()
        if self.state_or_province:
            fields["state_or_province_name"] = self.state_or_province.strip()
        if self.locality:
            fields["locality_name"] = self.locality.strip()
        return x509.Name.build(fields)


def build_distinguished_name(
    common_name: str,
    *,
    organization: str | None = None,
    organizational_unit: str | None = None,
    country: str | None = None,
    state_or_province: str | None = None,
    locality: str | None = None,
) -> x509.Name:
    return DistinguishedName(
        common_name=common_name,
        organization=organization,
        organizational_unit=organizational_unit,
        country=country,
        state_or_province=state_or_province,
        locality=locality,
    ).to_asn1()


def _normalize_algorithm_name(algorithm: str) -> str:
    return algorithm.strip().lower().replace("-", "_")


def signature_algorithm_identifier(algorithm: str) -> algos.SignedDigestAlgorithm:
    normalized = _normalize_algorithm_name(algorithm)
    if normalized == "rsa_pkcs1v15_sha256":
        return algos.SignedDigestAlgorithm({"algorithm": "sha256_rsa"})
    if normalized == "rsa_pkcs1v15_sha384":
        return algos.SignedDigestAlgorithm({"algorithm": "sha384_rsa"})
    if normalized == "rsa_pss_sha256":
        return algos.SignedDigestAlgorithm(
            {
                "algorithm": "rsassa_pss",
                "parameters": algos.RSASSAPSSParams(
                    {
                        "hash_algorithm": {"algorithm": "sha256"},
                        "mask_gen_algorithm": {
                            "algorithm": "mgf1",
                            "parameters": {"algorithm": "sha256"},
                        },
                        "salt_length": 32,
                        "trailer_field": 1,
                    }
                ),
            }
        )
    if normalized == "rsa_pss_sha384":
        return algos.SignedDigestAlgorithm(
            {
                "algorithm": "rsassa_pss",
                "parameters": algos.RSASSAPSSParams(
                    {
                        "hash_algorithm": {"algorithm": "sha384"},
                        "mask_gen_algorithm": {
                            "algorithm": "mgf1",
                            "parameters": {"algorithm": "sha384"},
                        },
                        "salt_length": 48,
                        "trailer_field": 1,
                    }
                ),
            }
        )
    if normalized == "ecdsa_sha256":
        return algos.SignedDigestAlgorithm({"algorithm": "sha256_ecdsa"})
    if normalized == "ecdsa_sha384":
        return algos.SignedDigestAlgorithm({"algorithm": "sha384_ecdsa"})

    raise ValueError(
        f"Unsupported X.509 signing algorithm '{algorithm}'. "
        "Use one of: rsa_pkcs1v15_sha256, rsa_pkcs1v15_sha384, "
        "rsa_pss_sha256, rsa_pss_sha384, ecdsa_sha256, ecdsa_sha384."
    )


def normalize_signature_for_algorithm(algorithm: str, signature: bytes) -> bytes:
    """
    Ensure signature bytes match X.509 DER expectations.

    PKCS#11 ECDSA implementations may return either DER sequence or raw r||s.
    """
    normalized = _normalize_algorithm_name(algorithm)
    if not normalized.startswith("ecdsa_"):
        return signature

    try:
        algos.DSASignature.load(signature)
        return signature
    except ValueError:
        if len(signature) % 2 != 0:
            raise ValueError("Invalid raw ECDSA signature length.")
        half = len(signature) // 2
        r = int.from_bytes(signature[:half], byteorder="big")
        s = int.from_bytes(signature[half:], byteorder="big")
        return algos.DSASignature({"r": r, "s": s}).dump()


def _load_pem_or_der(
    data: bytes | str,
    expected_pem_type: str,
) -> bytes:
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data

    if pem.detect(payload):
        pem_type, _headers, der_bytes = pem.unarmor(payload)
        if pem_type != expected_pem_type:
            raise ValueError(
                f"Expected PEM type '{expected_pem_type}', received '{pem_type}'."
            )
        return der_bytes
    return payload


def load_certificate(data: bytes | str) -> x509.Certificate:
    return x509.Certificate.load(_load_pem_or_der(data, "CERTIFICATE"))


def load_certificate_signing_request(data: bytes | str) -> csr.CertificationRequest:
    return csr.CertificationRequest.load(
        _load_pem_or_der(data, "CERTIFICATE REQUEST")
    )


def dump_certificate_pem(certificate: x509.Certificate) -> bytes:
    return pem.armor("CERTIFICATE", certificate.dump())


def dump_csr_pem(request: csr.CertificationRequest) -> bytes:
    return pem.armor("CERTIFICATE REQUEST", request.dump())


def generate_serial_number() -> int:
    # Positive 159-bit serial to satisfy common X.509 constraints.
    return int.from_bytes(os.urandom(20), byteorder="big") >> 1


def pkcs11_public_key_to_public_key_info(
    public_key: pkcs11.PublicKey,
) -> keys.PublicKeyInfo:
    key_type = public_key[Attribute.KEY_TYPE]
    if key_type == KeyType.RSA:
        modulus = int.from_bytes(public_key[Attribute.MODULUS], byteorder="big")
        exponent = int.from_bytes(
            public_key[Attribute.PUBLIC_EXPONENT], byteorder="big"
        )
        return keys.PublicKeyInfo(
            {
                "algorithm": {"algorithm": "rsa"},
                "public_key": keys.RSAPublicKey(
                    {
                        "modulus": modulus,
                        "public_exponent": exponent,
                    }
                ),
            }
        )

    if key_type == KeyType.EC:
        ec_params = public_key[Attribute.EC_PARAMS]
        ec_point = public_key[Attribute.EC_POINT]
        try:
            ec_point = core.OctetString.load(ec_point).native
        except ValueError:
            pass
        return keys.PublicKeyInfo(
            {
                "algorithm": {
                    "algorithm": "ec",
                    "parameters": keys.ECDomainParameters.load(ec_params),
                },
                "public_key": ec_point,
            }
        )

    raise ValueError(f"Unsupported public key type for X.509: {key_type}")


def build_ca_extensions(
    *,
    subject_public_key_info: keys.PublicKeyInfo,
    issuer_public_key_info: keys.PublicKeyInfo,
    path_length: int | None = None,
) -> x509.Extensions:
    basic_constraints_value: dict[str, bool | int] = {"ca": True}
    if path_length is not None:
        if path_length < 0:
            raise ValueError("path_length must be >= 0 when provided.")
        basic_constraints_value["path_len_constraint"] = path_length

    return x509.Extensions(
        [
            x509.Extension(
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": x509.BasicConstraints(basic_constraints_value),
                }
            ),
            x509.Extension(
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": x509.KeyUsage({"key_cert_sign", "crl_sign"}),
                }
            ),
            x509.Extension(
                {
                    "extn_id": "key_identifier",
                    "critical": False,
                    "extn_value": subject_public_key_info.sha1,
                }
            ),
            x509.Extension(
                {
                    "extn_id": "authority_key_identifier",
                    "critical": False,
                    "extn_value": x509.AuthorityKeyIdentifier(
                        {"key_identifier": issuer_public_key_info.sha1}
                    ),
                }
            ),
        ]
    )


def build_ca_csr_extensions(
    *,
    path_length: int | None = None,
) -> x509.Extensions:
    constraints: dict[str, bool | int] = {"ca": True}
    if path_length is not None:
        if path_length < 0:
            raise ValueError("path_length must be >= 0 when provided.")
        constraints["path_len_constraint"] = path_length

    return x509.Extensions(
        [
            x509.Extension(
                {
                    "extn_id": "basic_constraints",
                    "critical": True,
                    "extn_value": x509.BasicConstraints(constraints),
                }
            ),
            x509.Extension(
                {
                    "extn_id": "key_usage",
                    "critical": True,
                    "extn_value": x509.KeyUsage({"key_cert_sign", "crl_sign"}),
                }
            ),
        ]
    )


def _normalize_leaf_usage(usage: str) -> str:
    normalized = usage.strip().lower().replace("-", "_")
    aliases = {
        "server": "server",
        "client": "client",
        "both": "both",
        "server_client": "both",
        "client_server": "both",
    }
    resolved = aliases.get(normalized)
    if resolved is None:
        raise ValueError(
            f"Unsupported mTLS leaf usage '{usage}'. Use one of: server, client, both."
        )
    return resolved


def _leaf_eku_values(usage: str) -> list[str]:
    resolved = _normalize_leaf_usage(usage)
    if resolved == "server":
        return ["server_auth"]
    if resolved == "client":
        return ["client_auth"]
    return ["server_auth", "client_auth"]


def _build_dns_san_extension(dns_names: Iterable[str]) -> x509.Extension:
    normalized_names = [name.strip() for name in dns_names if name and name.strip()]
    if not normalized_names:
        raise ValueError("At least one non-empty DNS name is required for SAN extension.")
    general_names = x509.GeneralNames(
        [x509.GeneralName(name="dns_name", value=name) for name in normalized_names]
    )
    return x509.Extension(
        {
            "extn_id": "subject_alt_name",
            "critical": False,
            "extn_value": general_names,
        }
    )


def build_leaf_csr_extensions(
    *,
    usage: str = "server",
    dns_names: Iterable[str] | None = None,
) -> x509.Extensions:
    extensions: list[x509.Extension] = [
        x509.Extension(
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": x509.BasicConstraints({"ca": False}),
            }
        ),
        x509.Extension(
            {
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": x509.KeyUsage({"digital_signature", "key_encipherment"}),
            }
        ),
        x509.Extension(
            {
                "extn_id": "extended_key_usage",
                "critical": False,
                "extn_value": x509.ExtKeyUsageSyntax(_leaf_eku_values(usage)),
            }
        ),
    ]
    if dns_names:
        extensions.append(_build_dns_san_extension(dns_names))
    return x509.Extensions(extensions)


def _subject_common_name(subject: x509.Name) -> str | None:
    native = subject.native
    value = native.get("common_name")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def build_leaf_extensions(
    *,
    request: csr.CertificationRequest,
    issuer_public_key_info: keys.PublicKeyInfo,
    usage: str,
    dns_names: Iterable[str] | None = None,
) -> x509.Extensions:
    requested_extensions = get_requested_extensions(request)
    preserved: dict[str, x509.Extension] = {
        extension["extn_id"].native: extension for extension in requested_extensions
    }

    subject_public_key_info = request["certification_request_info"]["subject_pk_info"]
    subject = request["certification_request_info"]["subject"]
    final_dns_names = (
        [name.strip() for name in dns_names if name and name.strip()]
        if dns_names is not None
        else []
    )
    if not final_dns_names and "subject_alt_name" in preserved:
        san_ext = preserved["subject_alt_name"]
    else:
        if not final_dns_names:
            common_name = _subject_common_name(subject)
            if common_name:
                final_dns_names = [common_name]
        san_ext = _build_dns_san_extension(final_dns_names) if final_dns_names else None

    extensions: list[x509.Extension] = [
        x509.Extension(
            {
                "extn_id": "basic_constraints",
                "critical": True,
                "extn_value": x509.BasicConstraints({"ca": False}),
            }
        ),
        x509.Extension(
            {
                "extn_id": "key_usage",
                "critical": True,
                "extn_value": x509.KeyUsage({"digital_signature", "key_encipherment"}),
            }
        ),
        x509.Extension(
            {
                "extn_id": "extended_key_usage",
                "critical": False,
                "extn_value": x509.ExtKeyUsageSyntax(_leaf_eku_values(usage)),
            }
        ),
        x509.Extension(
            {
                "extn_id": "key_identifier",
                "critical": False,
                "extn_value": subject_public_key_info.sha1,
            }
        ),
        x509.Extension(
            {
                "extn_id": "authority_key_identifier",
                "critical": False,
                "extn_value": x509.AuthorityKeyIdentifier(
                    {"key_identifier": issuer_public_key_info.sha1}
                ),
            }
        ),
    ]
    if san_ext is not None:
        extensions.append(san_ext)

    for extension in requested_extensions:
        extn_id = extension["extn_id"].native
        if extn_id in {
            "basic_constraints",
            "key_usage",
            "extended_key_usage",
            "key_identifier",
            "authority_key_identifier",
            "subject_alt_name",
        }:
            continue
        extensions.append(extension)
    return x509.Extensions(extensions)


def create_certificate_signing_request(
    *,
    subject: x509.Name,
    subject_public_key_info: keys.PublicKeyInfo,
    sign_tbs: Callable[[bytes], bytes],
    signing_algorithm: str,
    extensions: x509.Extensions | None = None,
) -> csr.CertificationRequest:
    attributes: list[csr.CRIAttribute] = []
    if extensions is not None and len(extensions) > 0:
        attributes.append(
            csr.CRIAttribute(
                {
                    "type": "extension_request",
                    "values": [extensions],
                }
            )
        )

    request_info = csr.CertificationRequestInfo(
        {
            "version": "v1",
            "subject": subject,
            "subject_pk_info": subject_public_key_info,
            "attributes": attributes,
        }
    )

    signature = normalize_signature_for_algorithm(
        signing_algorithm,
        sign_tbs(request_info.dump()),
    )
    return csr.CertificationRequest(
        {
            "certification_request_info": request_info,
            "signature_algorithm": signature_algorithm_identifier(signing_algorithm),
            "signature": signature,
        }
    )


def create_self_signed_ca_certificate(
    *,
    subject: x509.Name,
    subject_public_key_info: keys.PublicKeyInfo,
    sign_tbs: Callable[[bytes], bytes],
    signing_algorithm: str,
    validity_days: int = 3650,
    path_length: int | None = 1,
    serial_number: int | None = None,
) -> x509.Certificate:
    if validity_days <= 0:
        raise ValueError("validity_days must be > 0.")
    resolved_serial = serial_number or generate_serial_number()

    not_before = datetime.now(timezone.utc) - timedelta(minutes=5)
    not_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
    signature_id = signature_algorithm_identifier(signing_algorithm)
    extensions = build_ca_extensions(
        subject_public_key_info=subject_public_key_info,
        issuer_public_key_info=subject_public_key_info,
        path_length=path_length,
    )

    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": resolved_serial,
            "signature": signature_id,
            "issuer": subject,
            "validity": x509.Validity(
                {
                    "not_before": x509.Time({"utc_time": not_before}),
                    "not_after": x509.Time({"utc_time": not_after}),
                }
            ),
            "subject": subject,
            "subject_public_key_info": subject_public_key_info,
            "extensions": extensions,
        }
    )

    signature = normalize_signature_for_algorithm(
        signing_algorithm,
        sign_tbs(tbs_certificate.dump()),
    )
    return x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": signature_id,
            "signature_value": signature,
        }
    )


def get_requested_extensions(
    request: csr.CertificationRequest,
) -> x509.Extensions:
    attributes = request["certification_request_info"]["attributes"]
    for attribute in attributes:
        if attribute["type"].native != "extension_request":
            continue
        values = attribute["values"]
        if len(values) > 0:
            return values[0]
    return x509.Extensions([])


def sign_csr_as_ca(
    *,
    issuer_certificate: x509.Certificate,
    request: csr.CertificationRequest,
    sign_tbs: Callable[[bytes], bytes],
    signing_algorithm: str,
    validity_days: int = 1825,
    path_length: int | None = 0,
    serial_number: int | None = None,
) -> x509.Certificate:
    if validity_days <= 0:
        raise ValueError("validity_days must be > 0.")
    resolved_serial = serial_number or generate_serial_number()

    issuer_subject = issuer_certificate["tbs_certificate"]["subject"]
    issuer_public_key_info = issuer_certificate["tbs_certificate"][
        "subject_public_key_info"
    ]
    subject = request["certification_request_info"]["subject"]
    subject_public_key_info = request["certification_request_info"]["subject_pk_info"]

    base_extensions = build_ca_extensions(
        subject_public_key_info=subject_public_key_info,
        issuer_public_key_info=issuer_public_key_info,
        path_length=path_length,
    )
    preserved_extensions = [
        extension
        for extension in get_requested_extensions(request)
        if extension["extn_id"].native
        not in {
            "basic_constraints",
            "key_usage",
            "key_identifier",
            "authority_key_identifier",
        }
    ]
    extensions = x509.Extensions([*base_extensions, *preserved_extensions])

    not_before = datetime.now(timezone.utc) - timedelta(minutes=5)
    not_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
    signature_id = signature_algorithm_identifier(signing_algorithm)
    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": resolved_serial,
            "signature": signature_id,
            "issuer": issuer_subject,
            "validity": x509.Validity(
                {
                    "not_before": x509.Time({"utc_time": not_before}),
                    "not_after": x509.Time({"utc_time": not_after}),
                }
            ),
            "subject": subject,
            "subject_public_key_info": subject_public_key_info,
            "extensions": extensions,
        }
    )
    signature = normalize_signature_for_algorithm(
        signing_algorithm,
        sign_tbs(tbs_certificate.dump()),
    )
    return x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": signature_id,
            "signature_value": signature,
        }
    )


def sign_csr_as_leaf(
    *,
    issuer_certificate: x509.Certificate,
    request: csr.CertificationRequest,
    sign_tbs: Callable[[bytes], bytes],
    signing_algorithm: str,
    usage: str = "server",
    validity_days: int = 397,
    serial_number: int | None = None,
    dns_names: Iterable[str] | None = None,
) -> x509.Certificate:
    if validity_days <= 0:
        raise ValueError("validity_days must be > 0.")
    resolved_serial = serial_number or generate_serial_number()
    resolved_usage = _normalize_leaf_usage(usage)

    issuer_subject = issuer_certificate["tbs_certificate"]["subject"]
    issuer_public_key_info = issuer_certificate["tbs_certificate"][
        "subject_public_key_info"
    ]
    subject = request["certification_request_info"]["subject"]
    subject_public_key_info = request["certification_request_info"]["subject_pk_info"]
    extensions = build_leaf_extensions(
        request=request,
        issuer_public_key_info=issuer_public_key_info,
        usage=resolved_usage,
        dns_names=dns_names,
    )

    not_before = datetime.now(timezone.utc) - timedelta(minutes=5)
    not_after = datetime.now(timezone.utc) + timedelta(days=validity_days)
    signature_id = signature_algorithm_identifier(signing_algorithm)
    tbs_certificate = x509.TbsCertificate(
        {
            "version": "v3",
            "serial_number": resolved_serial,
            "signature": signature_id,
            "issuer": issuer_subject,
            "validity": x509.Validity(
                {
                    "not_before": x509.Time({"utc_time": not_before}),
                    "not_after": x509.Time({"utc_time": not_after}),
                }
            ),
            "subject": subject,
            "subject_public_key_info": subject_public_key_info,
            "extensions": extensions,
        }
    )
    signature = normalize_signature_for_algorithm(
        signing_algorithm,
        sign_tbs(tbs_certificate.dump()),
    )
    return x509.Certificate(
        {
            "tbs_certificate": tbs_certificate,
            "signature_algorithm": signature_id,
            "signature_value": signature,
        }
    )


def default_x509_signing_algorithm_for_key(
    *,
    key_type: KeyType,
    ec_params: bytes | None = None,
    prefer_ca_profile: bool = False,
) -> str:
    if key_type == KeyType.RSA:
        return "rsa_pkcs1v15_sha384" if prefer_ca_profile else "rsa_pkcs1v15_sha256"
    if key_type == KeyType.EC:
        if ec_params is not None:
            try:
                curve = core.ObjectIdentifier.load(ec_params).native
                if curve in {"secp384r1", "1.3.132.0.34"}:
                    return "ecdsa_sha384"
            except ValueError:
                pass
        return "ecdsa_sha384" if prefer_ca_profile else "ecdsa_sha256"
    raise ValueError(f"Unsupported key type for X.509 signing defaults: {key_type}")
