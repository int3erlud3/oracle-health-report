"""Allow ``python -m oracle_health_report``."""

import sys

from .cli import main

sys.exit(main())
