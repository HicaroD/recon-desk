"""Exercise Firefox notebook documents, persistence, tab context and Markdown download.

WebDriver cannot address Firefox's native sidebar content directly. Drive the
unmodified sidebar document in a tab while the fixture is the active browser tab,
then use the real popup document to open and verify the native sidebar.

Run: python3 tests/notebook_firefox.py --firefox /Applications/Firefox.app/Contents/MacOS/firefox
Requires Selenium 4 and Firefox. Uses an isolated profile and local fixtures.
"""

import argparse
import http.server
import pathlib
import shutil
import tempfile
import threading

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.support.ui import Select, WebDriverWait


class Fixture(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'<!doctype html><title>Notebook fixture</title><h1>Research target</h1>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--firefox')
    parser.add_argument('--screenshot', type=pathlib.Path, help='Optional native sidebar screenshot')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='client-watcher-notebook-') as temporary:
        root = pathlib.Path(temporary)
        extension = root / 'extension'
        shutil.copytree(pathlib.Path(__file__).resolve().parents[1] / 'extension', extension)
        (extension / 'diagnostic.html').write_text('<!doctype html><title>Notebook test host</title><iframe id="popup" style="width:420px;height:700px"></iframe>')
        downloads = root / 'downloads'
        downloads.mkdir()
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        options = Options()
        if args.firefox:
            options.binary_location = args.firefox
        options.set_preference('browser.download.folderList', 2)
        options.set_preference('browser.download.dir', str(downloads))
        options.set_preference('browser.download.useDownloadDir', True)
        options.set_preference('browser.helperApps.neverAsk.saveToDisk', 'text/markdown')
        driver = None
        try:
            driver = webdriver.Firefox(options=options, service=Service(service_args=['--allow-system-access']))
            wait = WebDriverWait(driver, 10)
            driver.install_addon(str(extension), temporary=True)
            base = f'http://127.0.0.1:{server.server_port}'
            driver.get(base + '/account?token=omit#fragment')
            target = driver.current_window_handle
            driver.set_context('chrome')
            uuid = driver.execute_script("return WebExtensionPolicy.getByID('client-watcher@local.invalid').mozExtensionHostname")
            driver.set_context('content')
            target_id = None
            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/sidebar.html')
            notebook_tab = driver.current_window_handle
            target_id = driver.execute_async_script('''const done = arguments[0];
              browser.tabs.query({}).then(tabs => done(tabs.find(t => t.url.includes('/account?')).id));''')

            def sidebar():
                page()
                driver.switch_to.window(notebook_tab)
                driver.execute_async_script('''const id = arguments[0], done = arguments[1];
                  browser.tabs.update(id, {active:true}).then(() => done(true));''', target_id)
                wait.until(lambda d: d.find_element(By.ID, 'site').text == base)

            def page():
                driver.switch_to.default_content()
                driver.set_context('content')

            def click(id):
                wait.until(lambda d: d.find_element(By.ID, id).is_enabled())
                driver.find_element(By.ID, id).click()

            def write(id, value):
                field = driver.find_element(By.ID, id)
                field.clear()
                field.send_keys(value)

            sidebar()
            click('add-note')
            payload = '<img src=x onerror=alert(1)>\n```http\nGET /invoice/2\n```'
            write('note-text', payload)
            wait.until(lambda d: d.find_element(By.ID, 'editor-status').text == 'Draft saved locally')
            driver.refresh()
            sidebar()
            wait.until(lambda d: payload in d.find_element(By.ID, 'notes').text)
            assert not driver.find_elements(By.CSS_SELECTOR, '#notes img'), 'note content executed as markup'
            driver.find_element(By.CSS_SELECTOR, '.card-actions button').click()
            assert driver.find_element(By.ID, 'note-text').get_attribute('value') == payload
            write('note-tags', 'auth, idor')
            Select(driver.find_element(By.ID, 'note-progress')).select_by_visible_text('Testing')
            click('save-note')
            wait.until(lambda d: not d.find_element(By.ID, 'editor').is_displayed())
            assert driver.find_element(By.CSS_SELECTOR, '.note-source').get_attribute('href') == base + '/account'
            print('PASS real sidebar: draft recovery, safe text, tags, progress, sanitized page link', flush=True)

            # Keep an edit pinned to its original site while another origin becomes active.
            driver.find_element(By.CSS_SELECTOR, '.card-actions button').click()
            page()
            driver.switch_to.window(target)
            driver.switch_to.new_window('tab')
            other = driver.current_window_handle
            other_base = f'http://localhost:{server.server_port}'
            driver.get(other_base + '/other')
            driver.switch_to.window(notebook_tab)
            driver.execute_async_script('''const url = arguments[0], done = arguments[1];
              browser.tabs.query({}).then(tabs => browser.tabs.update(tabs.find(t => t.url === url).id, {active:true})).then(() => done(true));''', other_base + '/other')
            wait.until(lambda d: d.find_element(By.ID, 'site').text == other_base)
            assert driver.find_element(By.ID, 'editor-source').text == base + '/account'
            write('note-text', 'Pinned edit for original site')
            click('save-note')
            wait.until(lambda d: not d.find_element(By.ID, 'editor').is_displayed())
            assert 'No notes' in driver.find_element(By.ID, 'notebook-status').text
            page()
            driver.switch_to.window(other)
            driver.close()
            driver.switch_to.window(target)
            sidebar()
            wait.until(lambda d: 'Pinned edit for original site' in d.find_element(By.ID, 'notes').text)
            print('PASS real sidebar: active-site switching preserves original edit ownership', flush=True)

            click('add-note')
            write('note-text', payload)
            click('save-note')
            wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, '.note-card')) == 2)
            Select(driver.find_element(By.ID, 'filter-progress')).select_by_visible_text('Done')
            assert not driver.find_elements(By.CSS_SELECTOR, '.note-card')
            click('export-notes')
            exported = wait.until(lambda _: list(downloads.glob('*.md')))
            markdown = exported[0].read_text()
            assert payload in markdown and 'Pinned edit for original site' in markdown
            assert 'token=omit' not in markdown and '#fragment' not in markdown
            print('PASS real Markdown download: includes filtered-out notes and intact payloads', flush=True)

            # Load the real popup in an extension iframe after activating the
            # fixture. No production scripts are changed or injected.
            page()
            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/diagnostic.html')
            diagnostic = driver.current_window_handle
            driver.execute_async_script('''const id=arguments[0], done=arguments[1];
              browser.tabs.update(id, {active:true}).then(() => {
                document.getElementById('popup').src = 'popup.html'; done(true);
              });''', target_id)
            driver.switch_to.frame(driver.find_element(By.ID, 'popup'))
            save_finding = wait.until(lambda d: d.find_element(By.CSS_SELECTOR, '.finding button'))
            save_finding.click()
            wait.until(lambda d: d.find_element(By.CSS_SELECTOR, '.finding p:last-child').text)
            assert save_finding.text == 'Saved to notebook', driver.find_element(By.CSS_SELECTOR, '.finding').text
            click('open-notebook')
            wait.until(lambda d: d.execute_async_script('browser.sidebarAction.isOpen({}).then(arguments[0])'))
            if args.screenshot:
                driver.switch_to.default_content()
                driver.set_context('chrome')
                driver.save_screenshot(str(args.screenshot))
                driver.set_context('content')
            page()
            driver.switch_to.window(diagnostic)
            driver.close()
            driver.switch_to.window(target)
            sidebar()
            Select(driver.find_element(By.ID, 'filter-progress')).select_by_visible_text('All progress')
            wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, '.note-card')) == 3)
            assert driver.find_elements(By.CSS_SELECTOR, '.note-card details'), 'captured evidence is missing'
            print('PASS real popup: saves scanner evidence and opens the native Firefox sidebar', flush=True)

            # Reinstalling the same temporary add-on restarts extension contexts without clearing storage.
            page()
            driver.switch_to.window(target)
            driver.install_addon(str(extension), temporary=True)
            driver.switch_to.new_window('tab')
            driver.get(f'moz-extension://{uuid}/sidebar.html')
            notebook_tab = driver.current_window_handle
            sidebar()
            wait.until(lambda d: len(d.find_elements(By.CSS_SELECTOR, '.note-card')) == 3)
            print('PASS extension restart: persistent notebook retained', flush=True)
        finally:
            if driver:
                driver.quit()
            server.shutdown()


if __name__ == '__main__':
    main()
