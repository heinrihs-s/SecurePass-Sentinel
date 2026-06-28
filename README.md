# SecurePass Sentinel

Password policy and breach-exposure checker for defensive security reviews.

SecurePass Sentinel combines local policy checks, zxcvbn strength estimation, and the Have I Been Pwned k-anonymity API to help review password quality without storing plaintext passwords in reports.

Keywords: password security, password policy, Have I Been Pwned, zxcvbn, credential exposure, defensive security, Python.

## What It Does

- checks password length, character classes, and policy compliance
- estimates password strength with `zxcvbn`
- checks breached-password exposure using the HIBP range API
- supports interactive and batch modes
- exports batch results as JSON, CSV, or HTML
- masks passwords in generated batch reports

## Safety Notes

- Do not commit real password lists.
- Run batch analysis only on password material you are authorized to review.
- Treat reports as sensitive, even when passwords are masked.
- Prefer passphrases and password managers over hand-built complexity rules.

## Requirements

- Python 3.8+
- `requests`
- `zxcvbn`

Install:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Usage

Interactive mode:

```bash
python password_analyzer.py
```

Batch mode:

```bash
python password_analyzer.py passwords.txt
python password_analyzer.py passwords.txt csv
python password_analyzer.py passwords.txt html
```

## Output

The report includes:

- policy compliance
- breached-password status
- strength score
- estimated cracking resistance from zxcvbn
- remediation recommendations

## Agent-Friendly Ideas

Good tasks for Codex, Claude Code, or another coding agent:

- add `argparse` flags for policy settings
- add tests for policy checks and report formats
- add safer HTML escaping in the report writer
- split the analyzer into a small package and CLI entry point
- add redaction guidance for batch workflows

## License

MIT. See `LICENSE`.
