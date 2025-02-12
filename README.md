# SecurePass Sentinel 🛡️

A powerful password analysis tool that helps security professionals and organizations validate password policies, detect compromised credentials, and ensure password security compliance.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![HaveIBeenPwned](https://img.shields.io/badge/API-HaveIBeenPwned-red.svg)

## 🚀 Features

- **Comprehensive Password Analysis**
  - Policy compliance checking
  - Password strength scoring
  - Entropy calculation
  - Breach detection using HaveIBeenPwned API
  - Detailed recommendations for improvement

- **Flexible Processing Options**
  - Interactive single password analysis
  - Batch processing of password lists
  - Multiple output formats (JSON, CSV)

- **Security-First Design**
  - Password masking in reports
  - Secure API interactions
  - No password storage
  - Local processing

## 📋 Requirements

- Python 3.8+
- Required packages:
  ```
  requests>=2.28.0
  ```

## 🔧 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/securepass-sentinel.git
   cd securepass-sentinel
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## 💻 Usage

### Interactive Mode

Run the script without arguments to analyze a single password:

```bash
$ python password_analyzer.py
Enter password to analyze: MyP@ssw0rd2024

Password Analysis Report
==================================================

Policy Compliance:
- Meets Length: ✓
- Has Uppercase: ✓
- Has Lowercase: ✓
- Has Numbers: ✓
- Has Special: ✓
- Meets All Requirements: ✓

Breach Status: Password found in data breaches
Found in 45,678 breaches!

Strength Metrics:
- Length: 14
- Entropy: 45.60
- Overall Strength Score: 78/100

Recommendations:
- This password has been exposed in data breaches. Change it immediately!
```

### Batch Mode

Analyze multiple passwords from a file:

```bash
$ python password_analyzer.py passwords.txt
Starting batch analysis of 10 passwords...
Analyzing password 10/10...

Batch Analysis Summary
==================================================
Total passwords analyzed: 10
Policy compliant: 3 (30.0%)
Found in data breaches: 7 (70.0%)
Average strength score: 58.4/100

Results saved to passwords.analysis.json
```

### Input File Format

Create a text file with one password per line:
```
MyPassword123!
AnotherPassword456$
TestPass789#
```

### Output Formats

#### JSON Output
```json
{
  "results": [
    {
      "masked_password": "M*********!",
      "policy_compliance": {
        "meets_length": true,
        "has_uppercase": true,
        "has_lowercase": true,
        "has_numbers": true,
        "has_special": true,
        "meets_all_requirements": true
      },
      "breach_status": {
        "compromised": true,
        "breach_count": 120000,
        "status": "Password found in data breaches"
      },
      "strength_metrics": {
        "length": 11,
        "entropy": 38.5,
        "strength_score": 65
      },
      "recommendations": [
        "This password has been exposed in data breaches. Change it immediately!"
      ]
    }
  ]
}
```

#### CSV Output
```csv
masked_password,meets_all_requirements,length,entropy,strength_score,compromised,breach_count,recommendations
M*********!,true,11,38.5,65,true,120000,"This password has been exposed in data breaches. Change it immediately!"
```

## 🔒 Password Policy Configuration

Modify the `PasswordPolicy` settings in `password_analyzer.py` to match your organization's requirements:

```python
policy = PasswordPolicy(
    min_length=12,
    require_uppercase=True,
    require_lowercase=True,
    require_numbers=True,
    require_special=True,
    special_chars="!@#$%^&*()_+-=[]{}|;:,.<>?"
)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Future Enhancements

- [ ] Parallel processing for large password lists
- [ ] Additional output formats (PDF, HTML)
- [ ] Custom policy templates (NIST, OWASP, custom)
- [ ] Password generation suggestions
- [ ] Web interface with Flask/FastAPI
- [ ] Docker container support
- [ ] CI/CD pipeline integration

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [HaveIBeenPwned](https://haveibeenpwned.com/) for the breach detection API
- [NIST](https://pages.nist.gov/800-63-3/) for password security guidelines
- [OWASP](https://owasp.org/) for security best practices

## ⚠️ Disclaimer

This tool is intended for security professionals and organizational use. Always follow responsible security practices and applicable regulations when handling passwords.
