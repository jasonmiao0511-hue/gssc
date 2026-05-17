# GitHub Security Scanner (gssc) v1.2.0

Auto-scan GitHub repositories for security issues.

## Features

- 65 Security Checks
- Multi-language: Python, JS/TS, Go, Rust, Java, Ruby, PHP, C/C++
- GitHub Actions integration
- SARIF output for GitHub Advanced Security

## Quick Start

```bash
python scanner.py --repo https://github.com/owner/repo
python scanner.py --path /path/to/code --format sarif
```

## Checks by Language

| Language | Specific Checks |
|----------|----------------|
| Python | pickle, eval, SQL injection, SSRF |
| Go | exec.Command, db.Query, tls.Config |
| Rust | unsafe, unwrap, sqlx, Command |
| Java | Reflection, ObjectInputStream, ScriptEngine |
| JavaScript | eval, child_process, innerHTML |
| C/C++ | strcpy, malloc, buffer overflow |

## GitHub Actions

See `.github/workflows/security-scan.yml`

## License

MIT
