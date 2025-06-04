# WPScanner - WordPress Security Scanner

## Description

WPScanner is a Python-based command-line tool for scanning WordPress websites for common security misconfigurations, exposed sensitive files, plugin and theme vulnerabilities, outdated versions, and other typical weaknesses. It is designed for educational and assessment purposes and supports threaded execution for faster scanning.

---

## Features

- Detects the installed WordPress version and compares it to the latest official release.
- Scans for publicly exposed backup and sensitive files (e.g., `.env`, `wp-config.php`, `.git/config`).
- Detects directory listings in critical directories (`/plugins/`, `/themes/`, `/uploads/`).
- Checks for known brute-force protection plugins.
- Validates presence of important HTTP security headers.
- Verifies if the site uses HTTPS and whether it redirects HTTP to HTTPS.
- Inspects exposed REST API endpoints (`/wp-json/`).
- Identifies possible XSS vulnerabilities via basic payload checks.
- Detects default or common user profiles (`/author/admin`, etc.).
- Scans for presence of known vulnerable or malicious plugins/themes.
- Detects PHP version disclosure via headers.
- Evaluates script execution possibility in the uploads folder.
- Supports plugin version detection from readme/changelog files.
- CLI interface with multi-threaded plugin/theme checking.
- Supports optional logging to file.

---

## Requirements

- Python 3.7+
- Required libraries:
  - `requests`
  - `urllib3`

Install dependencies with:

pip install -r requirements.txt

## Usage

python3 scanner.py https://example.com

## Optional Arguments:

* -p, --plugins: Path to file with plugin slugs (one per line).
* -u, --user-agent: Custom User-Agent header.
* -t, --threads: Number of concurrent threads (default: 10).
* -l, --logfile: Output log file.

## Notes

* This tool performs only passive and non-intrusive checks.
* Do not use this scanner on websites you do not own or do not have explicit permission to test.
* Intended for ethical security testing, auditing, and educational use.

## License

This project is released under the MIT License.