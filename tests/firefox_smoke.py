"""Real Firefox regression: automatic badge updates, including BFCache restores.

Requires Selenium 4, Firefox and openssl. Selenium Manager resolves geckodriver.
The popup is never opened; diagnostics only read storage and badge text.
"""

import argparse
import http.server
import json
import pathlib
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
import time

from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from firefox_fixtures import CASES, REDACTED_VALUES, response


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        fixture = response(self.path)
        if fixture is not None:
            body, headers = fixture
            self.send_response(200)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        clean = self.path.startswith('/clean')
        script = self.path.startswith('/external.js')
        body = b'<!doctype html><title>Clean</title>' if clean else b'''<!doctype html>
          <title>Scan fixture</title><script>const key = "sb_secret_fixture12345678";</script>
          <script src="/external.js"></script>'''
        if script:
            body = b'const externalKey = "sb_secret_external12345678";'
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript' if script else 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Strict-Transport-Security', 'max-age=31536000')
        if clean:
            self.send_header('Content-Security-Policy', "default-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def check(driver, diagnostic, target, expected_url, label, clean=False, network=True, detection=None):
    fingerprint = 2166136261
    for char in expected_url:
        fingerprint = ((fingerprint ^ ord(char)) * 16777619) & 0xffffffff
    origin = '/'.join(expected_url.split('/')[:3])
    expected_page = f'{origin}#{fingerprint:x}'
    driver.switch_to.window(diagnostic)
    started = time.monotonic()
    result = None
    actual = set()
    while time.monotonic() - started < 5:  # Never let the 30s interval hide failure.
        result = driver.execute_async_script('''const url = arguments[0], done = arguments[1];
          (async () => {
            const tab = (await browser.tabs.query({})).find(t => t.url === url);
            if (!tab) return done(null);
            const state = (await browser.storage.local.get(`tab:${tab.id}`))[`tab:${tab.id}`];
            done({state, badge: await browser.action.getBadgeText({tabId: tab.id})});
          })().catch(e => done({error: String(e)}));''', expected_url)
        if (result and result.get('state', {}).get('status') == 'complete'
                and result['state'].get('url') == expected_page):
            findings = result['state']['findings']
            expected_badge = str(min(99, len(findings))) if findings else ''
            has_inline = any(f['ruleId'] == 'supabase-secret' for f in findings)
            coverage = result['state'].get('coverage', {})
            network_ready = not network or (coverage.get('headers') == 'checked'
                and (clean or coverage.get('externalScripts') == 'checked'))
            findings_ready = not findings if clean else has_inline
            if detection is not None:
                actual = {(f['ruleId'], f['evidence']) for f in findings}
                findings_ready = actual == detection['expected']
                network_ready = all(coverage.get(source) == 'checked' for source in [
                    'headers', 'cookies', 'storage', 'inlineScripts', 'forms',
                ]) and coverage.get('externalScripts') == (
                    'checked' if 'external' in detection else 'not-inspected')
                serialized = json.dumps(result['state'])
                for value in REDACTED_VALUES:
                    assert value not in serialized, f'{label}: persisted an unredacted fixture value'
            if network_ready and result['badge'] == expected_badge and findings_ready:
                driver.switch_to.window(target)
                driver.set_context('chrome')
                try:
                    deadline = time.monotonic() + 1
                    while True:
                        badge = driver.execute_script('''return document.querySelector(
                          '#client-watcher_local_invalid-browser-action .toolbarbutton-badge').textContent;''')
                        if badge == expected_badge or time.monotonic() >= deadline:
                            break
                        time.sleep(0.05)
                    assert badge == expected_badge, f'{label}: toolbar badge {badge!r} != {expected_badge!r}'
                finally:
                    driver.set_context('content')
                print(f'PASS {label}: toolbar badge={badge!r}, complete, '
                      f'{time.monotonic() - started:.2f}s', flush=True)
                return {f['ruleId'] for f in findings}
        time.sleep(0.05)
    missing = detection['expected'] - actual if detection is not None and result else None
    raise AssertionError(f'{label}: no expected findings/coverage/badge within 5s; missing={missing}: {result}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firefox', help='Firefox binary, if not discoverable')
    parser.add_argument('--extension-dir', type=pathlib.Path,
                        default=pathlib.Path(__file__).resolve().parents[1] / 'extension')
    args = parser.parse_args()
    implemented_rules = set(re.findall(r'finding\(\s*"([a-z-]+)"',
                                       (args.extension_dir / 'rules.js').read_text()))
    expected_rules = {rule for item in CASES for rule, _ in item['expected']}
    assert implemented_rules == expected_rules, (
        f'Update Firefox fixtures: uncovered rules={implemented_rules - expected_rules}, '
        f'unknown expectations={expected_rules - implemented_rules}')
    with tempfile.TemporaryDirectory(prefix='client-watcher-firefox-') as temporary:
        root = pathlib.Path(temporary)
        extension = root / 'extension'
        shutil.copytree(args.extension_dir, extension)
        # No production JS is modified or injected by this harness.
        (extension / 'diagnostic.html').write_text('<!doctype html><title>Read-only diagnostics</title>')
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(root / 'key.pem'), '-out', str(root / 'cert.pem'),
                        '-days', '1', '-subj', '/CN=localhost'],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        servers = [http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture) for _ in range(2)]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
        servers[1].socket = context.wrap_socket(servers[1].socket, server_side=True)
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        options = Options()
        if args.firefox:
            options.binary_location = args.firefox
        options.accept_insecure_certs = True  # Local self-signed HTTPS fixture only.
        driver = None
        try:
            driver = webdriver.Firefox(options=options, service=Service(service_args=['--allow-system-access']))
            print('Firefox', driver.capabilities['browserVersion'], flush=True)
            driver.install_addon(str(extension), temporary=True)
            driver.set_context('chrome')
            uuid = driver.execute_script("return WebExtensionPolicy.getByID('client-watcher@local.invalid').mozExtensionHostname")
            driver.execute_script('''window.CustomizableUI.addWidgetToArea(
              'client-watcher_local_invalid-browser-action', window.CustomizableUI.AREA_NAVBAR);''')
            driver.set_context('content')
            target = driver.current_window_handle
            # First navigation happens before opening even the read-only diagnostic page.
            first = f'http://127.0.0.1:{servers[0].server_port}/first'
            driver.get(first)
            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/diagnostic.html')
            diagnostic = driver.current_window_handle
            print('Permissions:', json.dumps(driver.execute_async_script(
                'browser.permissions.getAll().then(arguments[0])')), flush=True)
            check(driver, diagnostic, target, first, 'cold HTTP navigation')

            for scheme, server in zip(['http', 'https'], servers):
                base = f'{scheme}://127.0.0.1:{server.server_port}'
                a, b = base + '/a', base + '/b'
                driver.get(a)
                check(driver, diagnostic, target, a, scheme + ' navigation A')
                # This marker proves Firefox restored the document, rather than loading it anew.
                driver.execute_script('window.restored = false; addEventListener("pageshow", e => { window.restored = e.persisted; });')
                driver.get(b)
                check(driver, diagnostic, target, b, scheme + ' navigation B')
                driver.execute_script('window.restored = false; addEventListener("pageshow", e => { window.restored = e.persisted; });')
                driver.back()
                assert driver.execute_script('return window.restored') is True, 'Back did not exercise BFCache'
                check(driver, diagnostic, target, a, scheme + ' cached Back', network=False)
                driver.forward()
                assert driver.execute_script('return window.restored') is True, 'Forward did not exercise BFCache'
                check(driver, diagnostic, target, b, scheme + ' cached Forward', network=False)
                driver.refresh()
                check(driver, diagnostic, target, b, scheme + ' reload')
                driver.execute_script('history.pushState({}, "", "/spa")')
                check(driver, diagnostic, target, base + '/spa', scheme + ' SPA navigation')
                driver.execute_script('location.hash = "route"')
                check(driver, diagnostic, target, base + '/spa#route', scheme + ' fragment navigation')
                driver.get(base + '/clean')
                check(driver, diagnostic, target, base + '/clean', scheme + ' clears old badge', clean=True)
            observed_rules = set()
            for item in CASES:
                scheme = item.get('scheme', 'https')
                server = servers[0 if scheme == 'http' else 1]
                url = (f'{scheme}://127.0.0.1:{server.server_port}/detections/{item["name"]}/'
                       + item.get('suffix', ''))
                driver.get(url)
                observed_rules.update(check(driver, diagnostic, target, url,
                                            'detection ' + item['name'], detection=item))
            assert observed_rules == implemented_rules
            print(f'PASS all {len(implemented_rules)} detection rules across {len(CASES)} isolated cases', flush=True)
        finally:
            if driver:
                driver.quit()
            for server in servers:
                server.shutdown()
                server.server_close()


if __name__ == '__main__':
    main()
