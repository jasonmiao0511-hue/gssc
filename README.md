# GitHub Security Scanner (gssc)

Auto-scan GitHub repositories for common security issues.

## Features

- 🔍 **8 Security Checks**: Secrets, deserialization, SQL injection, SSRF, CORS, debug mode, insecure random, weak hash
- 📊 **Multiple Formats**: Table, JSON, SARIF (for GitHub integration)
- 🚀 **Easy to Use**: Single command to scan any repo
- 🎯 **Low False Positives**: Basic filtering for comments and test files

## Installation

```bash
git clone https://github.com/yourusername/gssc.git
cd gssc
pip install -r requirements.txt
```

## Usage

### Scan a GitHub repo
```bash
python scanner.py --repo https://github.com/owner/repo
```

### Scan local code
```bash
python scanner.py --path /path/to/code
```

### Output formats
```bash
# Table (default)
python scanner.py --repo URL

# JSON
python scanner.py --repo URL --format json

# SARIF (for GitHub Advanced Security)
python scanner.py --repo URL --format sarif
```

## Security Checks

| Check | Severity | Description |
|-------|----------|-------------|
| hardcoded_secret | CRITICAL | API keys, passwords in code |
| insecure_deserialization | HIGH | pickle, eval, exec usage |
| sql_injection | HIGH | String formatting in SQL |
| ssrf | MEDIUM | Unvalidated URL fetching |
| debug_mode | MEDIUM | Debug enabled in production |
| cors_wildcard | MEDIUM | CORS allows any origin |
| insecure_random | LOW | Weak random for security |
| insecure_hash | LOW | MD5/SHA1 usage |

## Example Output

```
================================================================================
GitHub Security Scanner v1.0.0
Target: https://github.com/example/app
Files Scanned: 42
Findings: 3
================================================================================

[CRITICAL] 1 finding(s)
--------------------------------------------------------------------------------
  File: config.py:15
  Check: hardcoded_secret
  Description: Potential hardcoded secret detected
  Code: API_KEY = "sk-live-1234567890abcdef"

[HIGH] 2 finding(s)
--------------------------------------------------------------------------------
  File: utils.py:42
  Check: insecure_deserialization
  Description: Insecure deserialization or code execution
  Code: data = pickle.loads(user_input)
```

## Roadmap

- [ ] More language support (Go, Rust, Java)
- [ ] Machine learning-based false positive reduction
- [ ] GitHub Action integration
- [ ] Web dashboard
- [ ] Enterprise features (SSO, reporting)

## License

MIT
