import requests
import hashlib
import re
import csv
import json
import sys
from typing import Any, Dict, List
from dataclasses import dataclass
from pathlib import Path
from zxcvbn import zxcvbn

@dataclass
class PasswordPolicy:
    min_length: int
    require_uppercase: bool
    require_lowercase: bool
    require_numbers: bool
    require_special: bool
    special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"

class PasswordAnalyzer:
    def __init__(self, policy: PasswordPolicy):
        self.policy = policy

    def check_password(self, password: str) -> Dict[str, bool]:
        """Analyze a password against the defined policy."""
        results = {
            "meets_length": len(password) >= self.policy.min_length,
            "has_uppercase": bool(re.search(r'[A-Z]', password)) if self.policy.require_uppercase else True,
            "has_lowercase": bool(re.search(r'[a-z]', password)) if self.policy.require_lowercase else True,
            "has_numbers": bool(re.search(r'\d', password)) if self.policy.require_numbers else True,
            "has_special": bool(set(password) & set(self.policy.special_chars)) if self.policy.require_special else True
        }
        results["meets_all_requirements"] = all(results.values())
        return results

    def check_haveibeenpwned(self, password: str) -> Dict[str, Any]:
        """Check if password has been exposed in data breaches using the HaveIBeenPwned API."""
        password_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = password_hash[:5], password_hash[5:]
        try:
            response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}")
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return {
                            "compromised": True,
                            "breach_count": int(count),
                            "status": "Password found in data breaches"
                        }
                return {
                    "compromised": False,
                    "breach_count": 0,
                    "status": "Password not found in known data breaches"
                }
        except requests.RequestException:
            return {
                "compromised": None,
                "breach_count": None,
                "status": "Error checking breach database"
            }

    def generate_report(self, password: str) -> Dict[str, Any]:
        """Generate a comprehensive password analysis report using zxcvbn for strength estimation."""
        policy_check = self.check_password(password)
        breach_check = self.check_haveibeenpwned(password)
        # Use zxcvbn for advanced password strength analysis
        zx_result = zxcvbn(password)
        report = {
            "policy_compliance": policy_check,
            "breach_status": breach_check,
            "strength_metrics": {
                "length": len(password),
                "entropy": zx_result["entropy"],
                "strength_score": zx_result["score"] * 25,  # converting score (0-4) to a 0-100 scale
                "zxcvbn_details": {
                    "guesses": zx_result["guesses"],
                    "guesses_log10": zx_result["guesses_log10"],
                    "crack_times_seconds": zx_result["crack_times_seconds"],
                    "calc_time": zx_result["calc_time"],
                }
            },
            "zxcvbn_feedback": zx_result["feedback"],
            "recommendations": self._generate_recommendations(
                policy_check, 
                breach_check, 
                zx_result["feedback"]
            )
        }
        return report

    def batch_analyze(self, input_file: str, output_format: str = 'json') -> None:
        """
        Analyze multiple passwords from a file and save results.
        
        Args:
            input_file: Path to a file containing passwords (one per line).
            output_format: 'json', 'csv', or 'html' for the output format.
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file {input_file} not found")
        
        # Read passwords from file
        with open(input_file, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        results = []
        total = len(passwords)
        print(f"Starting batch analysis of {total} passwords...")
        
        for i, password in enumerate(passwords, 1):
            print(f"Analyzing password {i}/{total}...", end='\r')
            report = self.generate_report(password)
            # Mask the password: show first and last character, with asterisks in between
            if len(password) > 4:
                masked = f"{password[0]}{'*' * (len(password)-2)}{password[-1]}"
            else:
                masked = "****"
            report["masked_password"] = masked
            results.append(report)
        
        print("\nAnalysis complete!")
        
        # Save results based on chosen format
        output_path = input_path.with_suffix(f'.analysis.{output_format}')
        if output_format == 'json':
            self._save_json_report(results, output_path)
        elif output_format == 'csv':
            self._save_csv_report(results, output_path)
        elif output_format == 'html':
            self._save_html_report(results, output_path)
        else:
            raise ValueError("Output format must be 'json', 'csv', or 'html'")
            
        print(f"Results saved to {output_path}")
        self._print_batch_summary(results)

    def _save_json_report(self, results: List[Dict], output_path: Path) -> None:
        """Save results in JSON format."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

    def _save_csv_report(self, results: List[Dict], output_path: Path) -> None:
        """Save results in CSV format."""
        # Flatten nested report data for CSV
        flattened_results = []
        for result in results:
            flat_result = {
                "masked_password": result["masked_password"],
                "meets_all_requirements": result["policy_compliance"]["meets_all_requirements"],
                "length": result["strength_metrics"]["length"],
                "entropy": result["strength_metrics"]["entropy"],
                "strength_score": result["strength_metrics"]["strength_score"],
                "compromised": result["breach_status"]["compromised"],
                "breach_count": result["breach_status"]["breach_count"],
                "recommendations": "; ".join(result["recommendations"])
            }
            flattened_results.append(flat_result)
            
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flattened_results[0].keys())
            writer.writeheader()
            writer.writerows(flattened_results)

    def _save_html_report(self, results: List[Dict], output_path: Path) -> None:
        """Save results in an HTML report format."""
        # Flatten nested report data similar to the CSV export
        flattened_results = []
        for result in results:
            flat_result = {
                "masked_password": result["masked_password"],
                "meets_all_requirements": result["policy_compliance"]["meets_all_requirements"],
                "length": result["strength_metrics"]["length"],
                "entropy": result["strength_metrics"]["entropy"],
                "strength_score": result["strength_metrics"]["strength_score"],
                "compromised": result["breach_status"]["compromised"],
                "breach_count": result["breach_status"]["breach_count"],
                "recommendations": "; ".join(result["recommendations"])
            }
            flattened_results.append(flat_result)
        
        # Build an HTML page with a table to display results
        html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Password Analysis Report</title>
<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    h1 { text-align: center; }
    table { width: 100%; border-collapse: collapse; margin-top: 20px; }
    th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr:nth-child(even) { background-color: #fafafa; }
</style>
</head>
<body>
<h1>Password Analysis Report</h1>
<table>
    <thead>
        <tr>
            <th>Masked Password</th>
            <th>Policy Compliant</th>
            <th>Length</th>
            <th>Entropy</th>
            <th>Strength Score</th>
            <th>Compromised</th>
            <th>Breach Count</th>
            <th>Recommendations</th>
        </tr>
    </thead>
    <tbody>
"""
        for item in flattened_results:
            html_content += f"""
        <tr>
            <td>{item['masked_password']}</td>
            <td>{'Yes' if item['meets_all_requirements'] else 'No'}</td>
            <td>{item['length']}</td>
            <td>{item['entropy']:.2f}</td>
            <td>{item['strength_score']}</td>
            <td>{'Yes' if item['compromised'] else 'No'}</td>
            <td>{item['breach_count'] if item['breach_count'] is not None else 'N/A'}</td>
            <td>{item['recommendations']}</td>
        </tr>
"""
        html_content += """
    </tbody>
</table>
</body>
</html>
"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)

    def _print_batch_summary(self, results: List[Dict]) -> None:
        """Print summary statistics for batch analysis."""
        total = len(results)
        compliant = sum(1 for r in results if r["policy_compliance"]["meets_all_requirements"])
        compromised = sum(1 for r in results if r["breach_status"]["compromised"])
        avg_score = sum(r["strength_metrics"]["strength_score"] for r in results) / total
        
        print("\nBatch Analysis Summary")
        print("=" * 50)
        print(f"Total passwords analyzed: {total}")
        print(f"Policy compliant: {compliant} ({(compliant/total)*100:.1f}%)")
        print(f"Found in data breaches: {compromised} ({(compromised/total)*100:.1f}%)")
        print(f"Average strength score: {avg_score:.1f}/100")

    def _generate_recommendations(self, policy_check: Dict[str, bool], breach_check: Dict[str, Any],
                                  zxcvbn_feedback: Dict[str, Any]) -> List[str]:
        """Generate recommendations for password improvement, including zxcvbn feedback."""
        recommendations = []
        if not policy_check["meets_all_requirements"]:
            if not policy_check["meets_length"]:
                recommendations.append(f"Increase password length to at least {self.policy.min_length} characters")
            if not policy_check["has_uppercase"]:
                recommendations.append("Add uppercase letters")
            if not policy_check["has_lowercase"]:
                recommendations.append("Add lowercase letters")
            if not policy_check["has_numbers"]:
                recommendations.append("Add numbers")
            if not policy_check["has_special"]:
                recommendations.append("Add special characters")
                
        if breach_check["compromised"]:
            recommendations.append("This password has been exposed in data breaches. Change it immediately!")
        
        # Incorporate zxcvbn feedback if available
        if zxcvbn_feedback:
            warning = zxcvbn_feedback.get("warning")
            suggestions = zxcvbn_feedback.get("suggestions", [])
            if warning:
                recommendations.append(warning)
            recommendations.extend(suggestions)
        
        if not recommendations:
            recommendations.append("Password meets all requirements!")
        return recommendations

def main():
    # Define a sample password policy
    policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_special=True
    )
    
    analyzer = PasswordAnalyzer(policy)
    
    # If a file path is provided as a command-line argument, run in batch mode.
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
        output_format = sys.argv[2] if len(sys.argv) > 2 else 'json'
        analyzer.batch_analyze(input_file, output_format)
    else:
        # Interactive mode for a single password
        password = input("Enter password to analyze: ")
        report = analyzer.generate_report(password)
        
        print("\nPassword Analysis Report")
        print("=" * 50)
        print("\nPolicy Compliance:")
        for check, passed in report["policy_compliance"].items():
            print(f"- {check.replace('_', ' ').title()}: {'PASS' if passed else 'FAIL'}")
        
        print("\nBreach Status:")
        print(f"- {report['breach_status']['status']}")
        if report['breach_status']['breach_count']:
            print(f"Found in {report['breach_status']['breach_count']} breaches!")
        
        print("\nStrength Metrics:")
        print(f"- Length: {report['strength_metrics']['length']}")
        print(f"- Entropy: {report['strength_metrics']['entropy']:.2f}")
        print(f"- Overall Strength Score: {report['strength_metrics']['strength_score']}/100")
        
        print("\nZXCVBN Feedback:")
        feedback = report.get("zxcvbn_feedback", {})
        if feedback.get("warning"):
            print(f"- Warning: {feedback.get('warning')}")
        if feedback.get("suggestions"):
            for suggestion in feedback.get("suggestions"):
                print(f"- Suggestion: {suggestion}")
        
        print("\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"- {rec}")

if __name__ == "__main__":
    main()
