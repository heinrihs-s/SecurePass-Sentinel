# SecurePass Sentinel 🛡️

A powerful password analysis tool that helps security professionals and organizations validate password policies, detect compromised credentials, and ensure password security compliance.

![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![HaveIBeenPwned](https://img.shields.io/badge/API-HaveIBeenPwned-red.svg)

## 🚀 Features

- **Comprehensive Password Analysis**
  - Policy compliance checking
  - Password strength scoring with advanced estimation using [zxcvbn](https://github.com/dropbox/zxcvbn)
  - Entropy calculation
  - Breach detection using the HaveIBeenPwned API
  - Detailed recommendations for improvement

- **Flexible Processing Options**
  - Interactive single password analysis
  - Batch processing of password lists
  - Multiple output formats (JSON, CSV, HTML)

- **Security-First Design**
  - Password masking in reports
  - Secure API interactions
  - No password storage
  - Local processing

## 📋 Requirements

- Python 3.8+
- Required packages:
  ```txt
  requests>=2.25.0
  zxcvbn>=4.4.28
  ```
*(For Python 3.6 support, you might also need: dataclasses>=0.8)*

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
Run the script without arguments to analyze a single password. Here's an example output:

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
- Estimated Crack Times:
  - Online Throttled: 5 hours
  - Unthrottled: 15 minutes
  - Offline Fast Hash: 0.5 seconds

Recommendations:
- This password has been exposed in data breaches. Change it immediately!
- Consider using a longer passphrase with more unique characters
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

Available output formats:
```bash
# JSON output (default)
python password_analyzer.py passwords.txt

# CSV output
python password_analyzer.py passwords.txt csv

# HTML output
python password_analyzer.py passwords.txt html
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
[
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
    "strength_metrics": {
      "length": 12,
      "entropy": 45.6,
      "strength_score": 85,
      "zxcvbn_details": {
        "guesses": 123456789,
        "guesses_log10": 8.09,
        "crack_times_seconds": {
          "online_throttling_100_per_hour": 12345,
          "offline_slow_hashing_1e4_per_second": 123,
          "offline_fast_hashing_1e10_per_second": 12
        },
        "calc_time": 0.01
      }
    },
    "breach_status": {
      "compromised": false,
      "breach_count": 0,
      "status": "Password not found in known data breaches"
    },
    "zxcvbn_feedback": {
      "warning": "",
      "suggestions": []
    },
    "recommendations": [
      "Password meets all requirements!"
    ]
  }
]
```

#### CSV Output
```csv
masked_password,meets_all_requirements,length,entropy,strength_score,compromised,breach_count,recommendations
M*********!,true,11,38.5,65,true,120000,"This password has been exposed in data breaches. Change it immediately!"
S**********4,false,10,22.4,35,false,0,"Increase password length to at least 12 characters; Add special characters"
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
- [ ] Additional output formats (PDF, enhanced HTML)
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
