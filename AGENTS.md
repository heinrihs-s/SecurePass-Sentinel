# Agent Instructions

This repository is a defensive password-policy and breach-exposure checker.

## Safety Rules

- Do not commit real password lists or report outputs from real users.
- Do not log plaintext passwords.
- Keep Have I Been Pwned usage in the k-anonymity range-query model.
- Treat generated reports as sensitive.

## Good Agent Tasks

- Add tests for policy checks and report generation.
- Add `argparse` options for policy settings.
- Escape HTML report fields.
- Split the code into a package plus CLI.
- Add synthetic fixtures only.

## Verification

```bash
python -m py_compile password_analyzer.py
```
