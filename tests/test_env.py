import os
from pathlib import Path

from secure_code_bench.env import load_dotenv


def test_load_dotenv_sets_missing_values(monkeypatch, tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text(
        """
# comment
OPENROUTER_API_KEY="from-file"
OPENROUTER_BASE_URL=https://example.test/api
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_BASE_URL", raising=False)

    load_dotenv(env_path)

    assert os.environ["OPENROUTER_API_KEY"] == "from-file"
    assert os.environ["OPENROUTER_BASE_URL"] == "https://example.test/api"


def test_load_dotenv_does_not_override_existing_env(monkeypatch, tmp_path: Path) -> None:
    env_path = tmp_path / ".env"
    env_path.write_text("OPENROUTER_API_KEY=from-file\n", encoding="utf-8")
    monkeypatch.setenv("OPENROUTER_API_KEY", "from-shell")

    load_dotenv(env_path)

    assert os.environ["OPENROUTER_API_KEY"] == "from-shell"
