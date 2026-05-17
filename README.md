# GitHub Security Scanner (gssc)

Auto-scan GitHub repositories for common security issues.

## Features

- 🔍 **45 Security Checks**: Comprehensive vulnerability detection
- 📊 **Multiple Formats**: Table, JSON, SARIF (for GitHub integration)
- 🚀 **Easy to Use**: Single command to scan any repo
- 🎯 **Low False Positives**: Basic filtering for comments and test files
- 🔧 **Multi-Language**: Python, JavaScript, Go, Java, Ruby, PHP, C/C++

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

## Security Checks (45 total)

### Critical (8)
| Check | Description |
|-------|-------------|
| hardcoded_secret | API keys, passwords in code |
| command_injection | os.system, subprocess with shell=True |
| jwt_none_alg | JWT "none" algorithm bypass |
| memory_unsafe | strcpy, strcat, sprintf (C/C++) |
| api_key_exposure | API key patterns |
| db_connection_string | MongoDB/Postgres/MySQL URLs |
| aws_key | AWS access keys |
| github_token | GitHub personal tokens |
| private_key | RSA/DSA/EC private keys |

### High (14)
| Check | Description |
|-------|-------------|
| insecure_deserialization | pickle, eval, exec |
| sql_injection | String formatting in SQL |
| path_traversal | ../ or path.join with user input |
| xxe | XML external entity |
| unsafe_file_upload | File upload handling |
| ldap_injection | LDAP query injection |
| nosql_injection | MongoDB $where injection |
| prototype_pollution | Object.assign, __proto__ |
| unsafe_dynamic_import | Dynamic import/require |
| buffer_overflow | malloc, strncpy (C/C++) |
| insecure_ssl | verify=False |
| ssti | Server-side template injection |
| xpath_injection | XPath query injection |
| regex_dos | ReDoS vulnerable regex |

### Medium (10)
| Check | Description |
|-------|-------------|
| ssrf | Unvalidated URL fetch |
| debug_mode | Debug enabled |
| cors_wildcard | CORS allows any origin |
| insecure_cookie | Missing Secure/HttpOnly |
| open_redirect | Unvalidated redirect |
| mass_assignment | params passed directly |
| weak_crypto | DES, 3DES, RC4 |
| csrf_missing | POST without CSRF |
| graphql_injection | GraphQL injection |
| integer_overflow | Integer multiplication |

### Low (6)
| Check | Description |
|-------|-------------|
| insecure_random | random.random for security |
| insecure_hash | MD5/SHA1 usage |
| timing_attack | String comparison |
| log_injection | User input in logs |
| clickjacking | X-Frame-Options check |
| information_disclosure | Stack traces in production |

### Info (7)
| Check | Description |
|-------|-------------|
| hardcoded_ip | IP addresses in code |
| sensitive_file | .env, .git/config references |
| hsts_missing | HSTS header check |
| content_type_missing | Content-Type security |
| race_condition | TOCTOU patterns |
| todo_fixme | Security-related TODOs |

## Example Output

```
================================================================================
GitHub Security Scanner v1.1.0
Target: https://github.com/example/app
Files Scanned: 42
Findings: 5
================================================================================

[CRITICAL] 2 finding(s)
--------------------------------------------------------------------------------
  File: config.py:15
  Check: hardcoded_secret
  Description: Potential hardcoded secret detected
  Code: API_KEY = "sk-live-1234567890abcdef"

  File: utils.py:42
  Check: command_injection
  Description: Command injection via shell execution
  Code: os.system(user_input)

[HIGH] 2 finding(s)
--------------------------------------------------------------------------------
  File: database.py:28
  Check: sql_injection
  Description: Potential SQL injection
  Code: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

[MEDIUM] 1 finding(s)
--------------------------------------------------------------------------------
  File: app.py:15
  Check: debug_mode
  Description: Debug mode enabled
  Code: DEBUG = True
```

## CI/CD Integration

### GitHub Actions
```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run GSSC
        run: |
          pip install -r requirements.txt
          python scanner.py --path . --format sarif
```

## Roadmap

- [x] 45 security checks
- [ ] Machine learning-based false positive reduction
- [ ] Web dashboard
- [ ] GitHub App integration
- [ ] Enterprise features (SSO, reporting)
- [ ] Custom rule engine

## License

MIT
