import requests
import argparse
import re
import sys
import logging
import json
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner():
    banner = r"""
    __        __            _ ____                    
    \ \      / /__  _ __ __| |  _ \ _ __ ___  ___ ___ 
     \ \ /\ / / _ \| '__/ _` | |_) | '__/ _ \/ __/ __|
      \ V  V / (_) | | | (_| |  __/| | |  __/\__ \__ \
       \_/\_/ \___/|_|  \__,_|_|   |_|  \___||___/___/
                                     Security Scanner
"""
    print(f"{Colors.BLUE}{banner}{Colors.RESET}")

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class WPScanner:
    def __init__(self, base_url, user_agent=None, max_workers=10, log_file=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        ua = user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36'
        self.session.headers.update({'User-Agent': ua})

        self.max_workers = max_workers

        # Setup logger
        self.logger = logging.getLogger('WPScanner')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(message)s')  # χωρίς timestamp

        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(formatter)
            self.logger.addHandler(fh)

    def print_ok(self, msg):
        self.logger.info(f"{Colors.GREEN}[OK]{Colors.RESET} {msg}")

    def print_warn(self, msg):
        self.logger.info(f"{Colors.YELLOW}[--]{Colors.RESET} {msg}")

    def print_err(self, msg):
        self.logger.info(f"{Colors.RED}[ERROR]{Colors.RESET} {msg}")

    def print_title(self, msg):
        self.logger.info(f"{Colors.BLUE}{msg}{Colors.RESET}")

    def request(self, path, allow_redirects=True, retries=3):
        url = self.base_url + path
        for attempt in range(retries):
            try:
                r = self.session.get(url, timeout=8, allow_redirects=allow_redirects, verify=False)
                return r
            except requests.RequestException as e:
                if attempt < retries -1:
                    continue
                self.print_err(f"Request to {url} failed: {e}")
                return None

    def check_wp_version(self):
        self.print_title("Checking WordPress version...")
        r = self.request('/readme.html')
        current_version = None
        if r and r.status_code == 200:
            match = re.search(r'Version (\d+\.\d+(\.\d+)?)', r.text)
            if match:
                current_version = match.group(1)
                self.print_ok(f"WordPress version: {current_version}")
        if not current_version:
            r = self.request('/')
            if r and r.status_code == 200:
                match = re.search(r'<meta name="generator" content="WordPress (\d+\.\d+(\.\d+)?)"', r.text)
                if match:
                    current_version = match.group(1)
                    self.print_ok(f"WordPress version (meta): {current_version}")

        if not current_version:
            self.print_warn("WordPress version not found")
            return None

        # Get latest version from WordPress API
        try:
            api_resp = requests.get('https://api.wordpress.org/core/version-check/1.7/', timeout=5)
            if api_resp.status_code == 200:
                data = api_resp.json()
                latest_version = data['offers'][0]['current']
                if latest_version == current_version:
                    self.print_ok(f"WordPress is up-to-date ({Colors.YELLOW}latest{Colors.RESET}: {latest_version})")
                else:
                    self.print_warn(f"WordPress is outdated. Current: {current_version}, Latest: {latest_version}")
            else:
                self.print_warn("Failed to fetch latest WordPress version info")
        except Exception as e:
            self.print_warn(f"Error fetching latest WordPress version: {e}")

        return current_version

    def check_exposed_backups(self):
        self.print_title("\nChecking for exposed backup files...")
        backup_files = [
            '/backup.zip',
            '/backup.tar.gz',
            '/wp-content/backup.zip',
            '/wp-content/backup.tar.gz',
            '/wp-content/uploads/backup.zip',
            '/wp-content/uploads/backup.tar.gz',
            '/wp-content/uploads/.htaccess',
            '/wp-content/uploads/.htpasswd',
        ]
        for f in backup_files:
            r = self.request(f)
            if r and r.status_code == 200 and len(r.content) > 100:
                self.print_warn(f"Backup or sensitive file exposed: {f}")
            else:
                self.print_ok(f"No exposed backup file at: {f}")

    def check_plugins_versions(self, plugins):
        self.print_title("\nChecking plugins existence and versions...")
        found_plugins = {}

        def check_plugin(plugin_slug):
            paths = [
                f'/wp-content/plugins/{plugin_slug}/readme.txt',
                f'/wp-content/plugins/{plugin_slug}/readme.md',
                f'/wp-content/plugins/{plugin_slug}/changelog.txt',
            ]
            version = None
            found = False
            for p in paths:
                r = self.request(p)
                if r and r.status_code == 200:
                    found = True
                    ver_patterns = [
                        r'Stable tag:\s*([\d\.]+)',
                        r'Version[:\s]*([\d\.]+)',
                        r'^\s*=\s*([\d\.]+)\s*=',
                        r'\*\s+([\d\.]+)\s+-\s+\d{4}-\d{2}-\d{2}',
                    ]
                    for pattern in ver_patterns:
                        match = re.search(pattern, r.text, re.IGNORECASE | re.MULTILINE)
                        if match:
                            version = match.group(1)
                            break
                    break  # Stop after first file found
            return (plugin_slug, found, version)


        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(check_plugin, plugin) for plugin in plugins]
            for future in as_completed(futures):
                plugin_slug, found, version = future.result()
                if found:
                    msg = f"Plugin '{plugin_slug}' found"
                    if version:
                        msg += f" ({Colors.GREEN}version:{Colors.RESET} {version})"
                    self.print_ok(msg)
                    found_plugins[plugin_slug] = version
                else:
                    self.print_warn(f"Plugin '{plugin_slug}' NOT found")

        return found_plugins

    def check_sensitive_files(self):
        self.print_title("\nChecking for exposed sensitive files...")
        sensitive_files = [
            '/wp-config.php',
            '/.env',
            '/.git/config',
            '/readme.html',
            '/license.txt',
            '/.htaccess',
            '/wp-includes/js/wp-emoji-release.min.js',
            '/robots.txt',
            '/xmlrpc.php',
            '/wp-admin/install.php',
            '/wp-content/debug.log',
        ]

        def check_file(f):
            r = self.request(f)
            if r and r.status_code == 200 and len(r.text) > 10:
                self.print_warn(f"Sensitive file exposed: {f}")
            else:
                self.print_ok(f"{f} not accessible")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(check_file, sensitive_files)

    def check_directory_listing(self):
        self.print_title("\nChecking directory listing...")
        dirs = [
            '/wp-content/uploads/',
            '/wp-content/plugins/',
            '/wp-content/themes/',
        ]

        def check_dir(d):
            r = self.request(d)
            if r and r.status_code == 200:
                if re.search(r'Index of /', r.text, re.I) or 'Parent Directory' in r.text:
                    self.print_warn(f"Directory listing ENABLED at {d}")
                else:
                    self.print_ok(f"No directory listing at {d}")
            else:
                self.print_ok(f"Directory {d} not accessible (likely no directory listing)")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(check_dir, dirs)

    def check_bruteforce_protection(self):
        self.print_title("\nChecking brute-force protection clues...")
        r = self.request('/wp-login.php')
        if not r:
            self.print_warn("Cannot access wp-login.php")
            return

        headers = r.headers
        brute_force_plugins = ['Wordfence', 'Limit Login Attempts', 'Loginizer']
        found = False
        for plugin in brute_force_plugins:
            for h in headers:
                if plugin.lower() in h.lower() or plugin.lower() in str(headers[h]).lower():
                    self.print_ok(f"Brute-force protection plugin detected in headers: {plugin}")
                    found = True
        if not found:
            if any(p.lower() in r.text.lower() for p in brute_force_plugins):
                self.print_ok("Brute-force protection plugin mention found in login page content")
                found = True
        if not found:
            self.print_warn("No brute-force protection plugin detected")

    def check_http_headers(self):
        self.print_title("\nChecking HTTP security headers...")
        r = self.request('/')
        if not r:
            self.print_warn("Cannot access homepage to check headers")
            return
        headers = r.headers
        checks = {
            'X-Frame-Options': 'Prevents clickjacking',
            'Content-Security-Policy': 'Mitigates XSS and data injection attacks',
            'X-Content-Type-Options': 'Prevents MIME-sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Referrer-Policy': 'Controls referrer info',
            'Permissions-Policy': 'Controls browser features',
        }
        for header, desc in checks.items():
            if header in headers:
                self.print_ok(f"{header}: {headers[header]}")
            else:
                self.print_warn(f"{header} header missing ({desc})")

    def check_ssl(self):
        self.print_title("\nChecking SSL / HTTPS...")
        if self.base_url.startswith('https'):
            self.print_ok("Site uses HTTPS")
        else:
            self.print_warn("Site does NOT use HTTPS")

        http_url = self.base_url.replace('https://', 'http://')
        try:
            r = requests.get(http_url, timeout=8, allow_redirects=False)
            if r.status_code in [301, 302] and 'https://' in r.headers.get('Location', ''):
                self.print_ok("HTTP redirects to HTTPS")
            else:
                self.print_warn("No HTTP->HTTPS redirect found")
        except Exception:
            self.print_warn("Could not check HTTP->HTTPS redirect")

    def check_php_version(self):
        self.print_title("\nChecking PHP version...")
        r = self.request('/')
        if r:
            server = r.headers.get('Server', '')
            x_powered = r.headers.get('X-Powered-By', '')
            php_version = None
            for header_val in [server, x_powered]:
                if 'PHP/' in header_val:
                    m = re.search(r'PHP/([\d\.]+)', header_val)
                    if m:
                        php_version = m.group(1)
                        break
            if php_version:
                self.print_ok(f"PHP version: {php_version}")
            else:
                self.print_warn("PHP version not disclosed in headers")
        else:
            self.print_warn("Cannot get homepage headers for PHP version check")

    def check_upload_exec(self):
        self.print_title("\nChecking upload directory for script execution...")
        test_files = [
            '/wp-content/uploads/test.php',
            '/wp-content/uploads/test.html',
        ]

        def check_exec(f):
            r = self.request(f)
            if r and r.status_code == 200:
                self.print_warn(f"Possible executable file accessible: {f}")
            else:
                self.print_ok(f"No executable file at: {f}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(check_exec, test_files)

    def check_vulnerable_endpoints(self):
        self.print_title("\nChecking popular vulnerable endpoints...")
        endpoints = [
            '/xmlrpc.php',
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/themes',
            '/wp-json/wp/v2/plugins',
            '/wp-login.php?action=register',
            '/wp-admin/admin-ajax.php',
            '/wp-content/debug.log',
            '/wp-admin/install.php',
            '/wp-json/oembed/1.0/embed',
            '/wp-json/wp/v2/posts',
        ]

        def check_endpoint(ep):
            r = self.request(ep)
            if r and r.status_code == 200:
                self.print_warn(f"Endpoint accessible: {ep}")
            else:
                self.print_ok(f"Endpoint not accessible or missing: {ep}")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            executor.map(check_endpoint, endpoints)

    def check_default_users(self):
        self.print_title("\nChecking default users existence (common usernames)...")
        common_users = ['admin', 'administrator', 'test', 'user']
        found_any = False
        for user in common_users:
            r = self.request(f'/author/{user}')
            if r and r.status_code == 200 and 'author' in r.text.lower():
                self.print_warn(f"Default user '{user}' might exist (author page accessible)")
                found_any = True
        if not found_any:
            self.print_ok("No default common users found")

    def check_xss_vulnerability(self):
        self.print_title("\nChecking for possible XSS vulnerabilities...")
        test_paths = [
            '/?s=<script>alert(1)</script>',
            '/wp-comments-post.php?comment=<script>alert(1)</script>',
        ]
        for path in test_paths:
            r = self.request(path)
            if r and '<script>alert(1)</script>' in r.text:
                self.print_warn(f"Possible XSS vulnerability detected at {path}")
            else:
                self.print_ok(f"No XSS detected at {path}")

    def check_htaccess_webconfig(self):
        self.print_title("\nChecking .htaccess and web.config exposure...")
        files = ['/.htaccess', '/web.config']
        for f in files:
            r = self.request(f)
            if r and r.status_code == 200:
                content_preview = r.text[:200].lower()
                # Απλός έλεγχος για κάποιες κοινές ευαισθησίες
                if 'deny from all' in content_preview or '<security>' in content_preview:
                    self.print_ok(f"{f} exists and contains security rules")
                else:
                    self.print_warn(f"{f} is exposed and might leak configuration info")
            else:
                self.print_ok(f"{f} not accessible or protected")

    def check_malicious_plugins_themes(self, known_bad_plugins=[], known_bad_themes=[]):
        self.print_title("\nChecking for known malicious or abandoned plugins/themes...")

        # Έλεγχος plugins
        for plugin in known_bad_plugins:
            r = self.request(f'/wp-content/plugins/{plugin}/readme.txt')
            if r and r.status_code == 200:
                self.print_warn(f"Known malicious/abandoned plugin detected: {plugin}")
            else:
                self.print_ok(f"Plugin '{plugin}' not found")

        # Έλεγχος themes
        for theme in known_bad_themes:
            r = self.request(f'/wp-content/themes/{theme}/style.css')
            if r and r.status_code == 200:
                self.print_warn(f"Known malicious/abandoned theme detected: {theme}")
            else:
                self.print_ok(f"Theme '{theme}' not found")
                
    def check_rest_api_exposure(self):
        self.print_title("\nChecking REST API data exposure...")
        endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/posts',
            '/wp-json/wp/v2/comments'
        ]
        for ep in endpoints:
            r = self.request(ep)
            if r and r.status_code == 200:
                try:
                    data = r.json()
                    if data:
                        self.print_warn(f"REST API endpoint {ep} exposes data (count: {len(data) if isinstance(data, list) else 'unknown'})")
                    else:
                        self.print_ok(f"REST API endpoint {ep} accessible but no data exposed")
                except Exception:
                    self.print_warn(f"REST API endpoint {ep} accessible but response not JSON")
            else:
                self.print_ok(f"REST API endpoint {ep} not accessible")


    def check_debug_mode(self):
        self.print_title("\nChecking if WordPress debug mode is enabled...")
        r = self.request('/wp-config.php')
        if r and r.status_code == 200:
            if re.search(r"define\s*\(\s*'WP_DEBUG'\s*,\s*true\s*\)", r.text, re.IGNORECASE):
                self.print_warn("WP_DEBUG is ENABLED in wp-config.php (debug mode active)")
            else:
                self.print_ok("WP_DEBUG is NOT enabled")
        else:
            self.print_warn("Cannot access wp-config.php to check debug mode (expected)")


    def check_admin_page(self):
        self.print_title("\nScanning for admin login page...")
        common_admin_paths = [
            '/wp-admin/',
            '/admin/',
            '/wp-login.php',
            '/login/',
            '/user/login/',
            '/administrator/',
            '/admin.php',
            '/admin/login.php',
        ]

        found = False
        for path in common_admin_paths:
            r = self.request(path)
            if r and r.status_code == 200:
                self.print_ok(f"Admin page found: {path}")
                found = True
        if not found:
            self.print_warn("No common admin login pages found")


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='WordPress Security Scanner')
    parser.add_argument('url', help='Target WordPress site URL')
    parser.add_argument('-p', '--plugins', help='File with plugin slugs list (one per line)')
    parser.add_argument('-u', '--user-agent', help='Custom User-Agent string')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads')
    parser.add_argument('-l', '--logfile', help='File to log output')
    args = parser.parse_args()

    scanner = WPScanner(args.url, user_agent=args.user_agent, max_workers=args.threads, log_file=args.logfile)

    wp_version = scanner.check_wp_version()

    plugins = []
    if args.plugins:
        try:
            with open(args.plugins, 'r') as f:
                plugins = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"Error reading plugins file: {e}")

    if plugins:
        scanner.check_plugins_versions(plugins)

    scanner.check_sensitive_files()
    scanner.check_directory_listing()
    scanner.check_bruteforce_protection()
    scanner.check_http_headers()
    scanner.check_ssl()
    scanner.check_php_version()
    scanner.check_upload_exec()
    scanner.check_vulnerable_endpoints()
    scanner.check_default_users()
    scanner.check_admin_page()
    scanner.check_exposed_backups()
    scanner.check_xss_vulnerability()
    scanner.check_htaccess_webconfig()

    known_bad_plugins = ['badplugin1', 'malwareplugin2']  # δικά σου δείγματα
    known_bad_themes = ['badtheme1', 'oldtheme2']
    scanner.check_malicious_plugins_themes(known_bad_plugins, known_bad_themes)

    scanner.check_rest_api_exposure()

    scanner.check_debug_mode()


    
if __name__ == '__main__':
    main()
