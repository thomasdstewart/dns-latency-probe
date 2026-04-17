# Contributing

Thanks for contributing.

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -c constraints.txt -e .[dev]
pre-commit install
```

## Quality gates

Before opening a PR, run:

```bash
ruff check .
black --check .
mypy
pytest
# optional coverage when pytest-cov is installed
pytest --cov=src/dns_latency_probe --cov-report=term-missing
```

## Style

- Keep code explicit and testable.
- Use type hints throughout.
- Prefer small, composable functions.
- Use structured logging over `print`.

## Pull requests

- Describe what changed and why.
- Include test evidence.
- Keep scope focused.
