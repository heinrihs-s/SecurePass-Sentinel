import requests
import hashlib
import re
import csv
import json
from typing import Dict, List
from dataclasses import dataclass
from pathlib import Path

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

    def check_haveibeenpwned(self, password: str) -> Dict[str, any]:
        """Check if password has been exposed in data breaches using HaveIBeenPwned API."""
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

    def generate_report(self, password: str) -> Dict[str, any]:
        """Generate a comprehensive password analysis report."""
        policy_check = self.check_password(password)
        breach_check = self.check_haveibeenpwned(password)
        
        entropy = self._calculate_entropy(password)
        
        return {
            "policy_compliance": policy_check,
            "breach_status": breach_check,
            "strength_metrics": {
                "length": len(password),
                "entropy": entropy,
                "strength_score": self._calculate_strength_score(password, policy_check, entropy)
            },
            "recommendations": self._generate_recommendations(policy_check, breach_check)
        }

    def batch_analyze(self, input_file: str, output_format: str = 'json') -> None:
        """
        Analyze multiple passwords from a file and save results.
        
        Args:
            input_file: Path to file containing passwords (one per line)
            output_format: 'json' or 'csv' for the output format
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file {input_file} not found")
            
        # Read passwords from file
        with open(input_file, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
            
        # Analyze each password
        results = []
        total = len(passwords)
        
        print(f"Starting batch analysis of {total} passwords...")
        
        for i, password in enumerate(passwords, 1):
            print(f"Analyzing password {i}/{total}...", end='\r')
            report = self.generate_report(password)
            
            # Add masked password to report (showing only first and last character)
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
        else:
            raise ValueError("Output format must be 'json' or 'csv'")
            
        print(f"Results saved to {output_path}")
        
        # Print summary statistics
        self._print_batch_summary(results)

    def _save_json_report(self, results: List[Dict], output_path: Path) -> None:
        """Save results in JSON format."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

    def _save_csv_report(self, results: List[Dict], output_path: Path) -> None:
        """Save results in CSV format."""
        # Flatten the nested dictionary structure for CSV
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
            
        # Write to CSV
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flattened_results[0].keys())
            writer.writeheader()
            writer.writerows(flattened_results)

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

    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy as a measure of complexity."""
        char_sets = {
            'lowercase': len(set(re.findall(r'[a-z]', password))),
            'uppercase': len(set(re.findall(r'[A-Z]', password))),
            'numbers': len(set(re.findall(r'\d', password))),
            'special': len(set(password) & set(self.policy.special_chars))
        }
        pool_size = sum(char_sets.values())
        return len(password) * (pool_size / 4) * 2

    def _calculate_strength_score(self, password: str, policy_check: Dict[str, bool], entropy: float) -> int:
        """Calculate a password strength score (0-100)."""
        base_score = min(100, entropy / 2)
        
        # Penalties for policy violations
        if not policy_check["meets_all_requirements"]:
            base_score *= 0.8
        
        return round(max(0, min(100, base_score)))

    def _generate_recommendations(self, policy_check: Dict[str, bool], breach_check: Dict[str, any]) -> List[str]:
        """Generate specific recommendations for password improvement."""
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
            
        return recommendations if recommendations else ["Password meets all requirements!"]

def main():
    # Example usage
    policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_numbers=True,
        require_special=True
    )
    
    analyzer = PasswordAnalyzer(policy)
    
    # Check if file path is provided as argument
    import sys
    if len(sys.argv) > 1:
        # Batch mode
        input_file = sys.argv[1]
        output_format = sys.argv[2] if len(sys.argv) > 2 else 'json'
        analyzer.batch_analyze(input_file, output_format)
    else:
        # Interactive mode
        password = input("Enter password to analyze: ")
        report = analyzer.generate_report(password)
        
        # Pretty print the report
        print("\nPassword Analysis Report")
        print("=" * 50)
        print(f"\nPolicy Compliance:")
        for check, passed in report["policy_compliance"].items():
            print(f"- {check.replace('_', ' ').title()}: {'✓' if passed else '✗'}")
        
        print(f"\nBreach Status: {report['breach_status']['status']}")
        if report['breach_status']['breach_count']:
            print(f"Found in {report['breach_status']['breach_count']} breaches!")
        
        print(f"\nStrength Metrics:")
        print(f"- Length: {report['strength_metrics']['length']}")
        print(f"- Entropy: {report['strength_metrics']['entropy']:.2f}")
        print(f"- Overall Strength Score: {report['strength_metrics']['strength_score']}/100")
        
        print("\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"- {rec}")

if __name__ == "__main__":
    main()
