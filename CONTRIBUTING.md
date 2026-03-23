# Contributing to CyberFlage Security

Thanks for contributing.

This project keeps collaboration lightweight and practical.

## Quick Workflow

1. Fork the repo
2. Create a branch from `main`
3. Make focused changes
4. Run tests
5. Open a PR

## Local Setup

```bash
pip install -r requirements.txt
pip install -e .
```

## Run Tests

```bash
pytest tests/test_detector.py
```

## PR Rules (Minimal)

- Keep PR scope small and clear
- Include what changed and why
- Mention config impact (if any)
- Add/update tests for logic changes
- Avoid unrelated refactors in same PR

## Commit Style

Use concise messages, for example:

- `fix: handle config path fallback`
- `feat: add feature logging CSV`
- `docs: update user guide`

## Need Help?

Open an issue with:

- expected behavior
- actual behavior
- steps to reproduce
- logs/output
