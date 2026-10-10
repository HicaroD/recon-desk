"""Synthetic, local-only detection cases for the real Firefox smoke suite.

Expectations are explicit rule/evidence pairs, independent of the rule engine.
Never put working credentials here. Every page clears its browser storage and
sets cookies only on its own path so cases cannot satisfy one another.
"""

import base64
import json
from urllib.parse import urlsplit


def encoded(value):
    return base64.b64encode(json.dumps(value).encode()).decode()


def jwt(role):
    def part(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')
    return f'{part({"alg": "HS256", "typ": "JWT"})}.{part({"iss": "supabase", "role": role})}.fakeSignature123'


SECRET = 'sb_secret_smokeFakeValue12345678'
TOKEN = 'smokeFakeTokenValue123456789012345'
SERVICE_ROLE = jwt('service_role')
ACCOUNT = {
    'type': 'service_account',
    'client_email': 'smoke@example.invalid',
    'private_key': '-----BEGIN PRIVATE KEY-----\nsmokeFakeKeyMaterial\n-----END PRIVATE KEY-----',
}
PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----\nsmokeFakeStandaloneKey\n-----END RSA PRIVATE KEY-----'
REDACTED_VALUES = [SECRET, TOKEN, SERVICE_ROLE, ACCOUNT['client_email'],
                   'smokeFakeKeyMaterial', 'smokeFakeStandaloneKey']
NONCE = 'c21va2VGaXh0dXJlTm9uY2U='
DEFAULT_HEADERS = [
    ('Content-Security-Policy', f"script-src 'self' 'nonce-{NONCE}'"),
    ('Strict-Transport-Security', 'max-age=31536000'),
]


def case(name, expected=(), **kwargs):
    return {'name': name, 'expected': set(expected), **kwargs}


CASES = []
for area in ['localStorage', 'sessionStorage']:
    for name, key, value, rule in [
        ('token', 'auth_token', TOKEN, 'storage-sensitive'),
        ('supabase', 'config', SECRET, 'supabase-secret'),
        ('service-role', 'config', SERVICE_ROLE, 'supabase-service-role'),
        ('firebase', 'config', json.dumps(ACCOUNT), 'firebase-service-account'),
    ]:
        CASES.append(case(f'{area}-{name}', [(rule, f'{area} key: {key}')],
                          storage={area: {key: value}}))

for source in ['inline', 'external']:
    label = 'Inline script 2' if source == 'inline' else 'External script'
    for name, script, rule in [
        ('supabase', f'const key = {json.dumps(SECRET)};', 'supabase-secret'),
        ('service-role', f'const key = {json.dumps(SERVICE_ROLE)};', 'supabase-service-role'),
        ('firebase', f'const account = {json.dumps(ACCOUNT)};', 'firebase-service-account'),
        ('private-key', f'const pem = {json.dumps(PRIVATE_KEY)};', 'private-key'),
        # The unused function is inspected without executing the unsafe sink.
        ('dom-sink', 'function unsafeSink(el) { el.innerHTML = location.hash; }', 'dom-location-html'),
        ('react-hydration', f'window.__INITIAL_STATE__ = {{"authToken": "{TOKEN}"}};', 'hydration-token'),
    ]:
        CASES.append(case(f'{source}-{name}', [(rule, label)], **{source: script}))

CASES.append(case('next-hydration', [
    ('next-runtime-config', 'Next.js hydration'),
    ('hydration-token', 'Next.js hydration'),
], html='<script id="__NEXT_DATA__" type="application/json">' + json.dumps({
    'props': {'authToken': TOKEN}, 'serverRuntimeConfig': {'internalValue': TOKEN},
}) + '</script>'))
CASES.append(case('password-form', [('password-form-http', 'Password form 1')],
                  html='<form action="http://example.invalid/login"><input type="password"></form>'))
CASES.append(case('url-query', [('url-sensitive', 'Query parameter: access_token')],
                  suffix=f'?access_token={TOKEN}'))
CASES.append(case('url-fragment', [('url-fragment-token', 'Fragment parameter: access_token')],
                  suffix=f'#access_token={TOKEN}'))
CASES.append(case('url-router-fragment', [('url-fragment-token', 'Fragment parameter: refresh_token')],
                  suffix=f'#/callback?refresh_token={TOKEN}'))
CASES.append(case('subrequest-query', [('url-sensitive', 'Query parameter: api_secret')],
                  html=f'<img src="/probe?api_secret={TOKEN}" alt="">'))
CASES.extend([
    case('cookies-https', [('cookie-httponly', 'Cookie: session_id'),
                          ('cookie-secure', 'Cookie: session_id')],
         cookies=[f'session_id={TOKEN}']),
    case('cookies-http', [('cookie-httponly', 'Cookie: sid')], scheme='http',
         cookies=[f'sid={TOKEN}']),
    case('cookies-protected', cookies=[f'session_id={TOKEN}; Secure; HttpOnly', 'theme=dark']),
])

for name, csp, hsts, expected in [
    ('missing-csp', None, 'max-age=31536000', ['header-csp']),
    ('missing-hsts', "script-src 'self'", None, ['header-hsts']),
    ('inline-csp', "script-src 'self' 'unsafe-inline'", 'max-age=31536000', ['header-csp-unsafe-inline']),
    ('wildcard-csp', 'script-src *', 'max-age=31536000', ['header-csp-wildcard-script']),
    ('unrelated-csp', "img-src 'self'", 'max-age=31536000', ['header-csp-no-script-restriction']),
    ('disabled-hsts', "script-src 'self'", 'max-age=0', ['header-hsts-disabled']),
    ('invalid-hsts', "script-src 'self'", 'max-age=abc', ['header-hsts-disabled']),
    ('nonce-csp', f"script-src 'unsafe-inline' 'nonce-{NONCE}'", 'max-age=31536000', []),
]:
    headers = [(key, value) for key, value in [
        ('Content-Security-Policy', csp), ('Strict-Transport-Security', hsts),
    ] if value is not None]
    CASES.append(case(name, [(rule, 'Main document response') for rule in expected], headers=headers))
CASES.extend([
    case('report-only-csp', [('header-csp', 'Main document response')], headers=[
        ('Content-Security-Policy-Report-Only', "script-src 'none'"),
        ('Strict-Transport-Security', 'max-age=31536000'),
    ]),
    case('multiple-csp', headers=[
        ('Content-Security-Policy', "script-src * 'unsafe-inline'"),
        ('Content-Security-Policy', "script-src 'self'"),
        ('Strict-Transport-Security', 'max-age=31536000'),
    ]),
    case('public-config', storage={'localStorage': {
        'supabase_anon_key': jwt('anon'),
        'supabase_publishable_key': 'sb_publishable_publicFixture12345',
        'firebase_apiKey': 'AIzaPublicFixtureConfig',
        'author': 'Public author metadata',
    }}, inline=f'''const publicConfig = {{
      supabase: "sb_publishable_publicFixture12345", anon: "{jwt('anon')}",
      firebase: {{apiKey: "AIzaPublicFixtureConfig", projectId: "demo"}}
    }};
    function safeSink(el) {{ el.textContent = location.hash; }}
    window.__INITIAL_STATE__ = {{"apiKey":"public-config"}};''',
         html='<script id="__NEXT_DATA__" type="application/json">{"serverRuntimeConfig":{}}</script>'
              '<form action="https://example.invalid/login"><input type="password"></form>'),
])
BY_NAME = {item['name']: item for item in CASES}


def response(path):
    """Return an HTTP fixture response, or None for the navigation fixtures."""
    path = urlsplit(path).path
    if path == '/probe':
        return b'', [('Content-Type', 'image/png')]
    if not path.startswith('/detections/'):
        return None
    name = path.split('/')[2]
    item = BY_NAME[name]
    if path.endswith('/script.js'):
        return item['external'].encode(), [('Content-Type', 'application/javascript')]
    # Encoding setup values keeps them out of inline-script detection. A storage
    # test must fail if storage scanning breaks, even if script scanning works.
    bootstrap = f'''localStorage.clear(); sessionStorage.clear();
      const setup = JSON.parse(atob("{encoded(item.get('storage', {}))}"));
      for (const [area, values] of Object.entries(setup))
        for (const [key, value] of Object.entries(values)) window[area].setItem(key, value);'''
    body = f'<!doctype html><title>{name}</title><script nonce="{NONCE}">{bootstrap}</script>'
    if 'inline' in item:
        body += f'<script nonce="{NONCE}">{item["inline"]}</script>'
    if 'external' in item:
        body += f'<script src="/detections/{name}/script.js"></script>'
    body += item.get('html', '')
    headers = list(item.get('headers', DEFAULT_HEADERS))
    headers.append(('Content-Type', 'text/html; charset=utf-8'))
    for cookie in item.get('cookies', []):
        headers.append(('Set-Cookie', f'{cookie}; Path=/detections/{name}/'))
    return body.encode(), headers
