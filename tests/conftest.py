"""Point the author registry at a test-only file (production registry ships empty).
The test file declares environment "test", so it is refused unless FINGUARD_ENV=test."""
import os
from pathlib import Path

os.environ.setdefault("FINGUARD_ENV", "test")
os.environ.setdefault("FINGUARD_AUTHORS_FILE", str(Path(__file__).parent / "fixtures_authors.json"))
