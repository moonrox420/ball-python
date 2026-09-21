import os
from pathlib import Path

import _pytest.pathlib

# Fix Windows Python 3.14 PermissionError on unlinking directory symlinks in pytest-of-*
_orig_cleanup = getattr(_pytest.pathlib, "cleanup_dead_symlinks", None)
if _orig_cleanup is not None:

    def _safe_cleanup_dead_symlinks(root: Path) -> None:
        try:
            for left_dir in root.iterdir():
                if left_dir.is_symlink():
                    try:
                        os.rmdir(left_dir)
                    except OSError:
                        try:
                            left_dir.unlink()
                        except OSError:
                            pass
        except OSError:
            pass

    _pytest.pathlib.cleanup_dead_symlinks = _safe_cleanup_dead_symlinks
