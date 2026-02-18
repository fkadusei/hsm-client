from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .exceptions import HsmConfigurationError


@dataclass(frozen=True)
class HsmConfig:
    """Runtime configuration for PKCS#11 HSM access."""

    module_path: str
    token_label: str | None = None
    slot_no: int | None = None
    user_pin_env: str = "HSM_USER_PIN"

    @classmethod
    def from_env(cls) -> "HsmConfig":
        module_path = os.environ.get("HSM_PKCS11_MODULE")
        token_label = os.environ.get("HSM_TOKEN_LABEL")
        slot_raw = os.environ.get("HSM_SLOT")
        user_pin_env = os.environ.get("HSM_USER_PIN_ENV", "HSM_USER_PIN")

        if not module_path:
            raise HsmConfigurationError("HSM_PKCS11_MODULE is required.")
        if not Path(module_path).exists():
            raise HsmConfigurationError(
                f"PKCS#11 module path does not exist: {module_path}"
            )

        slot_no: int | None = None
        if slot_raw:
            try:
                slot_no = int(slot_raw)
            except ValueError as exc:
                raise HsmConfigurationError(
                    f"HSM_SLOT must be an integer, got: {slot_raw}"
                ) from exc

        if not token_label and slot_no is None:
            raise HsmConfigurationError(
                "Set either HSM_TOKEN_LABEL or HSM_SLOT to locate the token."
            )

        return cls(
            module_path=module_path,
            token_label=token_label,
            slot_no=slot_no,
            user_pin_env=user_pin_env,
        )

    def user_pin(self) -> str:
        pin = os.environ.get(self.user_pin_env)
        if not pin:
            raise HsmConfigurationError(f"{self.user_pin_env} is required.")
        return pin
