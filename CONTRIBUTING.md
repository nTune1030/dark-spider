# Contributing to Dark Web Info Seek

Thank you for your interest in contributing! This document outlines the guidelines for contributing to this project.

## 🛡️ Code of Conduct

- Be respectful and constructive in all interactions.
- Do not share personal information (emails, phone numbers, etc.) in code or commits.
- Report security vulnerabilities privately — do not open public issues for security bugs.

## 🚀 Getting Started

1. **Fork** the repository.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/<your-username>/darkweb_info_seek.git
   cd darkweb_info_seek
   ```
3. **Set up** the environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/macOS
   .\.venv\Scripts\activate    # Windows
   pip install -e ".[dev]"
   playwright install chromium
   ```
4. **Copy** the config template:
   ```bash
   cp config_template.py core/config.py
   # Edit core/config.py with your local settings
   ```

## 🧪 Running Tests

```bash
pytest
```

Before submitting a PR, make sure all existing tests pass and add new tests for any new functionality.

## 📝 Code Style

- Follow **PEP 8** conventions.
- Use **lazy `%s` formatting** in all `logging` calls (not f-strings).
- Add **type hints** to all public function signatures.
- Keep imports at the **top of the file** — no mid-file imports.
- Use **parameterized SQL queries** — never f-strings or string concatenation in SQL.
- Escape all user-sourced values with `html.escape()` before embedding in HTML.

## 🔄 Pull Request Process

1. Create a **feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```
2. Make your changes with **clear, descriptive commit messages**.
3. Add or update **tests** for your changes.
4. Update **documentation** (README, docstrings) if applicable.
5. Ensure all tests pass: `pytest`
6. Open a PR with a **clear description** of the change and motivation.

## ⚠️ Security Guidelines

- **Never commit** `core/config.py` — it contains local settings.
- **Never commit** personal data (emails, phone numbers, API keys).
- **Never commit** database files (`.db`) or generated reports (`.html`).
- Use `INSERT OR IGNORE` / parameterized queries for all database operations.
- Always escape HTML output to prevent XSS.

## 📂 Project Structure

```
darkweb_info_seek/
├── core/           # Core libraries (config, db_manager, tor_manager, link_validator)
├── scripts/        # CLI utilities (keyword_manager, report_generator, etc.)
├── tests/          # Unit tests (pytest)
├── spider.py       # Main scanner logic
├── auto_spider.py  # Automated runner
└── config_template.py  # Template for core/config.py
```

## 🐛 Reporting Bugs

Open a [GitHub Issue](../../issues) with:
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS
- Relevant log output (redact any sensitive data)