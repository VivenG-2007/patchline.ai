# get_settings() is @lru_cache'd and env.py's checks only run once per
# process, so these are run as subprocesses (one Settings instance each)
# rather than importing app.config directly in this test process.

import subprocess
import sys

_CHECK_SNIPPET = """
import os
os.environ['ENVIRONMENT'] = '{environment}'
os.environ['CORS_ORIGINS'] = '{cors_origins}'
os.environ['JWT_PUBLIC_KEY_BASE64'] = 'cHVi'
from app.config import get_settings
get_settings()
print('SETTINGS_OK')
"""


def _run(environment: str, cors_origins: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-c", _CHECK_SNIPPET.format(environment=environment, cors_origins=cors_origins)],
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_wildcard_cors_rejected_in_production():
    result = _run("production", "*")
    assert result.returncode != 0
    assert "must not contain" in result.stderr


def test_explicit_origin_allowed_in_production():
    result = _run("production", "https://app.example.com")
    assert result.returncode == 0
    assert "SETTINGS_OK" in result.stdout


def test_wildcard_allowed_outside_production():
    # Wildcard CORS is still a bad idea in dev, but this guard is scoped to
    # production specifically so local/dev setups aren't broken by it.
    result = _run("development", "*")
    assert result.returncode == 0
    assert "SETTINGS_OK" in result.stdout
