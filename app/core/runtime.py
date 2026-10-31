"""Centralized thread-safe runtime configuration for ShopVuln lab mode."""

import logging
import threading
from typing import Literal

logger = logging.getLogger("shopvuln.runtime")

LabModeType = Literal["vulnerable", "fixed"]
VALID_LAB_MODES = ("vulnerable", "fixed")


class LabRuntimeConfig:
    """Thread-safe manager for the active lab operational mode.

    Supports runtime dynamic switching between 'vulnerable' and 'fixed' modes
    without requiring container or application restarts.
    """

    def __init__(self, initial_mode: str = "vulnerable"):
        self._lock = threading.Lock()
        self._mode: str = initial_mode if initial_mode in VALID_LAB_MODES else "vulnerable"

    def get_mode(self) -> str:
        """Return the currently active lab mode ('vulnerable' or 'fixed')."""
        with self._lock:
            return self._mode

    def set_mode(self, mode: str) -> str:
        """Switch the active lab mode in a thread-safe manner.

        Args:
            mode: The target mode, either 'vulnerable' or 'fixed'.

        Returns:
            The newly applied active lab mode.

        Raises:
            ValueError: If mode is not 'vulnerable' or 'fixed'.
        """
        mode_cleaned = mode.strip().lower() if isinstance(mode, str) else mode
        if mode_cleaned not in VALID_LAB_MODES:
            raise ValueError(
                f"Invalid lab mode: '{mode}'. Allowed modes are: {list(VALID_LAB_MODES)}"
            )

        with self._lock:
            old_mode = self._mode
            self._mode = mode_cleaned
            logger.info("Lab mode dynamically updated from '%s' to '%s'.", old_mode, mode_cleaned)

            # Synchronize with settings.LAB_MODE
            try:
                from app.config import settings
                super(settings.__class__, settings).__setattr__("LAB_MODE", mode_cleaned)
            except Exception:
                pass

            return self._mode

    def is_vulnerable(self) -> bool:
        """Check if the lab is currently operating in vulnerable mode."""
        return self.get_mode() == "vulnerable"

    def is_fixed(self) -> bool:
        """Check if the lab is currently operating in fixed mode."""
        return self.get_mode() == "fixed"


# Global singleton initialized from settings
from app.config import settings

runtime_config = LabRuntimeConfig(initial_mode=settings.LAB_MODE)
