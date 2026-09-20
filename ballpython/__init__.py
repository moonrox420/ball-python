"""ballpython - alias and entrypoint wrapper for pycleaner."""

from __future__ import annotations

from typing import Any

import pycleaner
from pycleaner import __all__ as __all__
from pycleaner import __version__ as __version__


def __getattr__(name: str) -> Any:
    return getattr(pycleaner, name)
