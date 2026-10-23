# Contributing to SentinelAI

Thank you for your interest in contributing to SentinelAI! We welcome pull requests, security audit improvements, scanner adapters, and documentation enhancements.

## Development Workflow

1. Fork the repository and clone it locally.
2. Set up Python virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r backend/requirements.txt
   ```
3. Set up frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```
4. Run automated test suite:
   ```bash
   pytest -v
   ruff check backend/
   ```
5. Ensure Next.js builds cleanly:
   ```bash
   cd frontend
   npm run build
   ```
6. Commit your changes with descriptive messages adhering to Conventional Commits:
   - `feat(...)`: New capability
   - `fix(...)`: Bug fix
   - `test(...)`: Adding or updating tests
   - `docs(...)`: Documentation changes
7. Submit a pull request to `main`.
