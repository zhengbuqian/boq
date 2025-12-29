"""
boq - Universal isolated development environment.

Uses kernel overlayfs for full POSIX compliance (including file locking).
"""

from .config import Config
from .core import Boq, BoqError, list_boqs, check_dependencies

__all__ = ["Config", "Boq", "BoqError", "list_boqs", "check_dependencies"]
