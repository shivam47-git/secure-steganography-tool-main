"""
Pytest configuration: ensure the project root is on ``sys.path`` so that the
``steganography``, ``encryption`` and ``utils`` modules can be imported from
the ``tests/`` directory regardless of where pytest is invoked from.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
