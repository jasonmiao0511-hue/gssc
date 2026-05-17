#!/usr/bin/env python3
"""
GitHub Security Scanner (gssc)
Auto-scan GitHub repos for common security issues
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

class GitHubSecurityScanner:
    VERSION = "1.1.0"
    
    # Security patterns to detect
    PATTERNS = {
        "hardcoded_secret": {
            "pattern": r'(password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[=:]\s*["\'][^"\']{8,}["\']',
            "severity": "CRITICAL",
            "description": "Potential hardcoded secret detected"
        },
        "insecure_deserialization": {
            "pattern": r'(pickle\.loads|yaml\.load\(|eval\(|exec\()',
            "severity": "HIGH",
            "description": "Insecure deserialization or code execution"
        },
        "sql_injection": {
            "pattern": r'(execute\s*\(.*%s|f"SELECT.*\{.*\}|f"INSERT.*\{.*\})',
            "severity": "HIGH",
            "description": "Potential SQL injection"
        },
        "ssrf": {
            "pattern": r'(requests\.get\(|urllib\.request\.urlopen\(|curl\s+)',
            "severity": "MEDIUM",
            "description": "Potential SSRF - unvalidated URL fetch"
        },
        "insecure_random": {
            "pattern": r'(random\.random\(\)|random\.randint|Math\.random\(\))',
            "severity": "LOW",
            "description": "Insecure random for security purposes"
        },
        "debug_mode": {
            "pattern": r'(DEBUG\s*=\s*True|debug:\s*true|app\.run\(.*debug\s*=\s*True)',
            "severity": "MEDIUM",
            "description": "Debug mode enabled"
        },
        "cors_wildcard": {
            "pattern": r'(Access-Control-Allow-Origin:\s*\*|cors.*origin.*\*)',
            "severity": "MEDIUM",
            "description": "CORS wildcard - allows any origin"
        },
        "insecure_hash": {
            "pattern": r'(md5|sha1)\s*\(',
            "severity": "LOW",
            "description": "Weak hash algorithm"
        },
        "command_injection": {
            "pattern": r'(os\.system\(|subprocess\.call\(.*shell\s*=\s*True|subprocess\.run\(.*shell\s*=\s*True|eval\()',
            "severity": "CRITICAL",
            "description": "Command injection via shell execution"
        },
        "path_traversal": {
            "pattern": r'(open\(.*\+.*\)|\.\./|\.\.\\\\|path\.join\(.*req\.)|send_file\(.*\+.*\))',
            "severity": "HIGH",
            "description": "Potential path traversal"
        },
        "xxe": {
            "pattern": r'(xml\.etree\.ElementTree\.parse|lxml\.etree\.parse|DocumentBuilderFactory|SAXParserFactory)',
            "severity": "HIGH",
            "description": "Potential XXE - XML external entity"
        },
        "insecure_cookie": {
            "pattern": r'(Set-Cookie.*(?!Secure)(?!HttpOnly)|cookie.*secure\s*=\s*False|SESSION_COOKIE_SECURE\s*=\s*False)',
            "severity": "MEDIUM",
            "description": "Insecure cookie settings"
        },
        "hardcoded_ip": {
            "pattern": r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            "severity": "INFO",
            "description": "Hardcoded IP address"
        },
        "sensitive_file": {
            "pattern": r'(\.env|\.htaccess|\.git/config|\.ssh/id_rsa|\.aws/credentials|secrets\.json|config\.json)',
            "severity": "MEDIUM",
            "description": "Reference to sensitive file"
        },
        "jwt_none_alg": {
            "pattern": r'(algorithm\s*=\s*["\']none["\']|alg\s*:\s*["\']none["\'])',
            "severity": "CRITICAL",
            "description": "JWT with none algorithm - authentication bypass"
        },
        "unsafe_file_upload": {
            "pattern": r'(multipart\.form\.get\(|request\.files\[|FileUpload|\.save\(.*request)',
            "severity": "HIGH",
            "description": "Unsafe file upload handling"
        },
        "ldap_injection": {
            "pattern": r'(ldap.*search\(.*\+|ldap.*filter\(.*\+|DirectorySearcher\()',
            "severity": "HIGH",
            "description": "Potential LDAP injection"
        },
        "nosql_injection": {
            "pattern": r'(find\(\{.*\$where.*\}|find\(\{.*\$regex.*\}|\.find\(.*req\.)',
            "severity": "HIGH",
            "description": "Potential NoSQL injection"
        },
        "open_redirect": {
            "pattern": r'(redirect\(.*req\.|Location\s*:\s*.*\+|window\.location\s*=\s*.*\+)',
            "severity": "MEDIUM",
            "description": "Potential open redirect"
        },
        "mass_assignment": {
            "pattern": r'(params\[:.*\]|req\.body\.|update_attributes\(|update\(.*params)',
            "severity": "MEDIUM",
            "description": "Potential mass assignment vulnerability"
        },
        "timing_attack": {
            "pattern": r'(==\s*.*password|==\s*.*secret|==\s*.*token|compare\s*.*==)',
            "severity": "LOW",
            "description": "Potential timing attack - string comparison"
        },
        "log_injection": {
            "pattern": r'(log\(.*\+|logger\(.*\+|console\.log\(.*req\.)',
            "severity": "LOW",
            "description": "Potential log injection"
        },
        "prototype_pollution": {
            "pattern": r'(Object\.assign\(|__proto__|constructor\.prototype|\.merge\()',
            "severity": "HIGH",
            "description": "Potential prototype pollution"
        },
        "regex_dos": {
            "pattern": r'(re\.search\(.*\(.*\*|re\.match\(.*\(.*\*|RegExp\(.*\(.*\*)',
            "severity": "MEDIUM",
            "description": "Potential ReDoS - regex denial of service"
        },
        "unsafe_dynamic_import": {
            "pattern": r'(import\(.*\+|require\(.*\+|__import__\(.*\+|load_module\()',
            "severity": "HIGH",
            "description": "Unsafe dynamic import"
        },
        "memory_unsafe": {
            "pattern": r'(strcpy\(|strcat\(|sprintf\(|gets\(|memcpy\(|memmove\()',
            "severity": "CRITICAL",
            "description": "Memory unsafe function (C/C++)"
        },
        "buffer_overflow": {
            "pattern": r'(malloc\(|alloca\(|realloc\(|strncpy\(.*\d+\))',
            "severity": "HIGH",
            "description": "Potential buffer overflow"
        },
        "integer_overflow": {
            "pattern": r'(int.*\*.*int|short.*\*.*short|long.*\*.*long)',
            "severity": "MEDIUM",
            "description": "Potential integer overflow"
        },
        "race_condition": {
            "pattern": r'(fopen\(.*["\']w|open\(.*O_RDWR|File\.createNewFile\()',
            "severity": "MEDIUM",
            "description": "Potential race condition (TOCTOU)"
        },
        "information_disclosure": {
            "pattern": r'(stacktrace|traceback|Exception\(|Error\(|\.printStackTrace\()',
            "severity": "LOW",
            "description": "Information disclosure via error messages"
        },
        "insecure_ssl": {
            "pattern": r'(verify\s*=\s*False|verify_ssl\s*=\s*False|ssl_verify\s*=\s*False|NODE_TLS_REJECT_UNAUTHORIZED.*0)',
            "severity": "HIGH",
            "description": "SSL/TLS certificate verification disabled"
        },
        "weak_crypto": {
            "pattern": r'(DES|3DES|RC4|Blowfish|ECB mode|CBC mode)',
            "severity": "MEDIUM",
            "description": "Weak cryptographic algorithm"
        },
        "ssti": {
            "pattern": r'(render_template_string\(|render_template\(.*\+|\.render\(.*req\.|\.template\(.*\+)',
            "severity": "HIGH",
            "description": "Potential SSTI - server-side template injection"
        },
        "csrf_missing": {
            "pattern": r'(form.*method\s*=\s*["\']post["\']|@app\.route.*methods.*POST|router\.post\()',
            "severity": "MEDIUM",
            "description": "Form without CSRF protection (check manually)"
        },
        "clickjacking": {
            "pattern": r'(X-Frame-Options|frame-ancestors|iframe.*src)',
            "severity": "LOW",
            "description": "Clickjacking protection (check manually)"
        },
        "hsts_missing": {
            "pattern": r'(Strict-Transport-Security|max-age)',
            "severity": "INFO",
            "description": "HSTS header (check manually)"
        },
        "content_type_missing": {
            "pattern": r'(Content-Type|X-Content-Type-Options)',
            "severity": "INFO",
            "description": "Content-Type security headers (check manually)"
        },
        "xpath_injection": {
            "pattern": r'(xpath\(.*\+|evaluate\(.*\+|selectNodes\(.*\+)',
            "severity": "HIGH",
            "description": "Potential XPath injection"
        },
        "graphql_injection": {
            "pattern": r'(graphql\(.*\+|query\s*\{.*\$|mutation\s*\{.*\$)',
            "severity": "MEDIUM",
            "description": "Potential GraphQL injection"
        },
        "api_key_exposure": {
            "pattern": r'(api[_-]?key\s*[:=]\s*["\'][^"\']{16,}["\']|apikey\s*[:=]\s*["\'][^"\']{16,}["\'])',
            "severity": "CRITICAL",
            "description": "API key exposed in code"
        },
        "db_connection_string": {
            "pattern": r'(mongodb(\+srv)?://|postgres(ql)?://|mysql://|redis://|connection_string)',
            "severity": "CRITICAL",
            "description": "Database connection string exposed"
        },
        "aws_key": {
            "pattern": r'(AKIA[0-9A-Z]{16}|aws_access_key_id|aws_secret_access_key)',
            "severity": "CRITICAL",
            "description": "AWS credentials exposed"
        },
        "github_token": {
            "pattern": r'(gh[pousr]_[A-Za-z0-9_]{36,}|github[_-]?token)',
            "severity": "CRITICAL",
            "description": "GitHub token exposed"
        },
        "private_key": {
            "pattern": r'(BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY|BEGIN SSH2 ENCRYPTED PRIVATE KEY)',
            "severity": "CRITICAL",
            "description": "Private key exposed"
        },
        "todo_fixme": {
            "pattern": r'(TODO.*fix|FIXME.*security|HACK.*|XXX.*|BUG.*)',
            "severity": "INFO",
            "description": "TODO/FIXME comment - may indicate unfinished security work"
        }
    }
    
    def __init__(self, repo_url=None, local_path=None, output_format="table"):
        self.repo_url = repo_url
        self.local_path = local_path
        self.output_format = output_format
        self.findings = []
        self.files_scanned = 0
        
    def clone_repo(self):
        """Clone repo if URL provided"""
        if not self.repo_url:
            return True
            
        repo_name = self.repo_url.split('/')[-1].replace('.git', '')
        self.local_path = f"/tmp/gssc_{repo_name}_{int(datetime.now().timestamp())}"
        
        print(f"[*] Cloning {self.repo_url}...")
        r = subprocess.run(
            ["git", "clone", "--depth", "1", self.repo_url, self.local_path],
            capture_output=True, text=True, timeout=60
        )
        
        if r.returncode != 0:
            print(f"[!] Clone failed: {r.stderr}")
            return False
            
        print(f"[+] Cloned to {self.local_path}")
        return True
        
    def scan_file(self, file_path):
        """Scan a single file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except:
            return
            
        rel_path = str(file_path).replace(self.local_path, '').lstrip('/\\')
        
        for check_name, check in self.PATTERNS.items():
            for line_num, line in enumerate(lines, 1):
                if re.search(check["pattern"], line, re.IGNORECASE):
                    # Reduce false positives
                    if self._is_false_positive(line, check_name):
                        continue
                        
                    self.findings.append({
                        "file": rel_path,
                        "line": line_num,
                        "check": check_name,
                        "severity": check["severity"],
                        "description": check["description"],
                        "code": line.strip()[:100]
                    })
                    
    def _is_false_positive(self, line, check_name):
        """Basic false positive reduction"""
        # Skip comments
        if line.strip().startswith('#') or line.strip().startswith('//'):
            return True
        # Skip example/test files
        if 'example' in line.lower() or 'test' in line.lower():
            return True
        # Skip documentation
        if 'README' in line or 'CHANGELOG' in line:
            return True
        return False
        
    def scan_directory(self):
        """Scan all files in directory"""
        if not self.local_path:
            print("[!] No path to scan")
            return
            
        path = Path(self.local_path)
        
        # Supported file extensions
        extensions = {'.py', '.js', '.ts', '.go', '.java', '.rb', '.php', '.c', '.cpp', '.h'}
        
        print(f"[*] Scanning {self.local_path}...")
        
        for ext in extensions:
            for file_path in path.rglob(f"*{ext}"):
                # Skip common non-source directories
                if any(d in str(file_path) for d in ['node_modules', '.git', 'vendor', 'dist', 'build', '__pycache__']):
                    continue
                    
                self.files_scanned += 1
                self.scan_file(file_path)
                
        print(f"[+] Scanned {self.files_scanned} files")
        
    def generate_report(self):
        """Generate scan report"""
        if self.output_format == "json":
            return json.dumps({
                "scanner": "gssc",
                "version": self.VERSION,
                "timestamp": datetime.now().isoformat(),
                "repo": self.repo_url or self.local_path,
                "files_scanned": self.files_scanned,
                "findings_count": len(self.findings),
                "findings": self.findings
            }, indent=2)
            
        elif self.output_format == "sarif":
            # SARIF format for GitHub integration
            return self._generate_sarif()
            
        else:  # table
            return self._generate_table()
            
    def _generate_table(self):
        """Generate table format report"""
        lines = []
        lines.append("=" * 80)
        lines.append(f"GitHub Security Scanner v{self.VERSION}")
        lines.append(f"Target: {self.repo_url or self.local_path}")
        lines.append(f"Files Scanned: {self.files_scanned}")
        lines.append(f"Findings: {len(self.findings)}")
        lines.append("=" * 80)
        
        if not self.findings:
            lines.append("\n[+] No security issues found!")
            return '\n'.join(lines)
            
        # Group by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        by_severity = {s: [] for s in severity_order}
        for f in self.findings:
            by_severity[f["severity"]].append(f)
            
        for severity in severity_order:
            findings = by_severity[severity]
            if not findings:
                continue
                
            lines.append(f"\n[{severity}] {len(findings)} finding(s)")
            lines.append("-" * 80)
            
            for f in findings:
                lines.append(f"  File: {f['file']}:{f['line']}")
                lines.append(f"  Check: {f['check']}")
                lines.append(f"  Description: {f['description']}")
                lines.append(f"  Code: {f['code']}")
                lines.append("")
                
        return '\n'.join(lines)
        
    def _generate_sarif(self):
        """Generate SARIF format for GitHub Advanced Security"""
        # Simplified SARIF
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "gssc",
                        "version": self.VERSION
                    }
                },
                "results": []
            }]
        }
        
        for f in self.findings:
            sarif["runs"][0]["results"].append({
                "ruleId": f["check"],
                "level": f["severity"].lower(),
                "message": {"text": f["description"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {"startLine": f["line"]}
                    }
                }]
            })
            
        return json.dumps(sarif, indent=2)
        
    def cleanup(self):
        """Remove cloned repo"""
        if self.repo_url and self.local_path and '/tmp/' in self.local_path:
            subprocess.run(["rm", "-rf", self.local_path], capture_output=True)
            
    def run(self):
        """Main scan flow"""
        print(f"[*] GitHub Security Scanner v{self.VERSION}")
        print(f"[*] Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        if self.repo_url:
            if not self.clone_repo():
                return 1
                
        if not self.local_path or not Path(self.local_path).exists():
            print("[!] Invalid path")
            return 1
            
        self.scan_directory()
        
        report = self.generate_report()
        print("\n" + report)
        
        # Save report
        report_file = f"gssc_report_{int(datetime.now().timestamp())}.json"
        if self.output_format == "table":
            report_file = report_file.replace('.json', '.txt')
            
        with open(report_file, 'w') as f:
            f.write(report)
        print(f"\n[+] Report saved to {report_file}")
        
        self.cleanup()
        return 0

def main():
    parser = argparse.ArgumentParser(
        description="GitHub Security Scanner - Find security issues in code"
    )
    parser.add_argument(
        "--repo", "-r",
        help="GitHub repo URL to scan"
    )
    parser.add_argument(
        "--path", "-p",
        help="Local path to scan"
    )
    parser.add_argument(
        "--format", "-f",
        choices=["table", "json", "sarif"],
        default="table",
        help="Output format"
    )
    parser.add_argument(
        "--version", "-v",
        action="version",
        version=f"%(prog)s {GitHubSecurityScanner.VERSION}"
    )
    
    args = parser.parse_args()
    
    if not args.repo and not args.path:
        parser.print_help()
        print("\n[!] Error: Must specify --repo or --path")
        return 1
        
    scanner = GitHubSecurityScanner(
        repo_url=args.repo,
        local_path=args.path,
        output_format=args.format
    )
    
    return scanner.run()

if __name__ == "__main__":
    sys.exit(main())
