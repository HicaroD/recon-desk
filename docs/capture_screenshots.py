"""Capture ReconDesk's real Firefox UI using an isolated profile and local demo data.

Requires Selenium 4, Pillow, and Firefox. No production extension files are changed.
"""

import argparse
import http.server
import json
import pathlib
import shutil
import tempfile
import threading

from PIL import Image
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import WebDriverWait


DEMO = b'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>Demo shop | Account</title>
<style>
  * { box-sizing: border-box; } body { margin: 0; color: #253346; background: #f4f6fa;
    font: 15px/1.6 system-ui, sans-serif; } nav { padding: 22px 36px; background: white;
    border-bottom: 1px solid #dce2eb; } nav strong { color: #225f53; margin-right: 32px; }
  nav span { color: #657389; } main { max-width: 760px; padding: 52px 36px; margin: auto; }
  h1 { font-size: 30px; margin: 8px 0; } h2 { font-size: 17px; margin: 0 0 18px; }
  .label { color: #488171; font-size: 11px; font-weight: bold; letter-spacing: .12em; }
  .muted { color: #657389; } section { margin-top: 28px; padding: 26px; background: white;
    border: 1px solid #dce2eb; border-radius: 12px; } .row { display: flex;
    justify-content: space-between; padding: 13px 0; border-top: 1px solid #edf0f5; }
  .pill { border-radius: 20px; color: #225f53; background: #e5f5ee; padding: 2px 12px; }
  aside { margin-top: 28px; font-size: 12px; color: #657389; }
</style>
<nav><strong>DEMO SHOP</strong><span>Account &nbsp; / &nbsp; Billing &nbsp; / &nbsp; Settings</span></nav>
<main><div class="label">RESEARCH FIXTURE</div><h1>Account overview</h1>
<p class="muted">A local demo website for ReconDesk screenshots.</p>
<section><h2>Workspace</h2><div class="row"><span>Account</span><strong>Research team</strong></div>
<div class="row"><span>Plan</span><span class="pill">Team</span></div>
<div class="row"><span>Role</span><strong>Member</strong></div></section>
<section><h2>Recent invoices</h2><div class="row"><span>INV-1042</span><span>View invoice</span></div>
<div class="row"><span>INV-1041</span><span>View invoice</span></div></section>
<aside>Local fixtures only. Credentials and research notes in this demo are fictional.</aside>
</main><script type="application/json">{"key":"sb_secret_recondesk_demo_only_12345678"}</script></html>'''


class DemoSite(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(DEMO)

    def log_message(self, *args):
        pass


def optimize(path):
    with Image.open(path) as image:
        image.save(path, optimize=True)


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firefox', help='Firefox executable, if not discoverable')
    parser.add_argument('--output', type=pathlib.Path, default=root / 'docs' / 'screenshots')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='recondesk-screenshots-') as temporary:
        extension = pathlib.Path(temporary) / 'extension'
        shutil.copytree(root / 'extension', extension)
        # WebDriver can inspect the popup document in a frame, but not the native
        # Firefox popup. Both use the same unmodified packaged HTML/CSS/JS.
        (extension / 'capture.html').write_text(
            '<!doctype html><title>ReconDesk capture</title>'
            '<iframe id="popup" style="border:0;width:400px;height:720px"></iframe>')
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), DemoSite)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        options = Options()
        if args.firefox:
            options.binary_location = args.firefox
        options.set_preference('layout.css.devPixelsPerPx', '1.0')
        driver = None
        try:
            driver = webdriver.Firefox(options=options, service=Service(service_args=['--allow-system-access']))
            driver.set_window_rect(width=1320, height=1060)
            wait = WebDriverWait(driver, 15)
            manifest = json.loads((extension / 'manifest.json').read_text())
            driver.install_addon(str(extension), temporary=True)
            base = f'http://127.0.0.1:{server.server_port}'
            driver.get(base + '/account')
            target = driver.current_window_handle
            driver.set_context('chrome')
            uuid = driver.execute_script('return WebExtensionPolicy.getByID(arguments[0]).mozExtensionHostname',
                                         manifest['browser_specific_settings']['gecko']['id'])
            driver.set_context('content')
            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/sidebar.html')
            notebook = driver.current_window_handle
            target_id = driver.execute_async_script('''const url=arguments[0], done=arguments[1];
              browser.tabs.query({}).then(tabs => done(tabs.find(t => t.url === url).id));''', base + '/account')

            def activate_target():
                driver.execute_async_script('''const id=arguments[0], done=arguments[1];
                  browser.tabs.update(id, {active:true}).then(() => done(true));''', target_id)

            activate_target()
            wait.until(lambda d: d.find_element(By.ID, 'site').text == base)
            for id, path, text, tags, progress in [
                ('surface', '/account', 'Mapped account and billing flows.\nKeep two demo accounts ready for comparison.', ['recon', 'auth'], 'Done'),
                ('ownership', '/billing', 'Check invoice ownership across accounts.\nNext: compare the same invoice request as a second user.', ['idor', 'billing'], 'Testing'),
            ]:
                result = driver.execute_async_script('''const msg=arguments[0], done=arguments[1];
                  browser.runtime.sendMessage(msg).then(done);''', {
                    'type': 'notebook-request', 'action': 'save', 'url': base + path, 'revision': 0,
                    'note': {'id': id, 'text': text, 'tags': tags, 'progress': progress, 'draft': False},
                })
                assert result.get('note'), result

            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/capture.html')
            capture = driver.current_window_handle
            driver.execute_async_script('''const id=arguments[0], done=arguments[1];
              browser.tabs.update(id, {active:true}).then(() => {
                document.getElementById('popup').src='popup.html'; done(true);
              });''', target_id)
            driver.switch_to.frame(driver.find_element(By.ID, 'popup'))
            wait.until(lambda d: d.find_element(By.ID, 'summary').text == '1 finding')
            wait.until(lambda d: 'HIGH' in d.find_element(By.CSS_SELECTOR, '.finding').text)
            driver.find_element(By.TAG_NAME, 'body').screenshot(str(args.output / 'findings.png'))
            driver.find_element(By.CSS_SELECTOR, '.finding button').click()
            wait.until(lambda d: d.find_element(By.CSS_SELECTOR, '.finding button').text == 'Saved to notebook')
            driver.find_element(By.ID, 'open-notebook').click()
            wait.until(lambda d: d.execute_async_script('browser.sidebarAction.isOpen({}).then(arguments[0])'))
            driver.switch_to.default_content()
            driver.switch_to.window(capture)
            driver.close()
            driver.switch_to.window(target)
            driver.set_context('chrome')
            driver.save_screenshot(str(args.output / 'notebook.png'))
            driver.execute_script('window.SidebarController.hide()')
            driver.set_context('content')

            # Capture the editor at a sidebar-like width with real autosave.
            driver.switch_to.window(notebook)
            driver.set_window_rect(width=480, height=1060)
            activate_target()
            wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, '.note-card')) == 3)
            driver.find_elements(By.CSS_SELECTOR, '.card-actions button:first-child')[1].click()
            text = driver.find_element(By.ID, 'note-text')
            text.send_keys('\n\nGET /api/invoices/1042\nCompare status, owner, and response fields.')
            wait.until(lambda d: d.find_element(By.ID, 'editor-status').text == 'Draft saved locally')
            driver.execute_script('arguments[0].setSelectionRange(0, 0); arguments[0].scrollTop = 0;', text)
            driver.find_element(By.ID, 'editor').screenshot(str(args.output / 'note-editor.png'))
            for name in ['findings.png', 'notebook.png', 'note-editor.png']:
                path = args.output / name
                optimize(path)
                print(f'Captured {path} ({path.stat().st_size // 1024} KiB)', flush=True)
        finally:
            if driver:
                driver.quit()
            server.shutdown()


if __name__ == '__main__':
    main()
