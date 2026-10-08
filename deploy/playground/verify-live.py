#!/usr/bin/env python3
"""Check deployed cookie contracts without credentials or sign-in.

Only cookie names are reported. Authorization URLs and cookie values remain
in memory; redirects are deliberately not followed.
"""
import http.cookies
import json
import subprocess
import urllib.error
import urllib.request

CONTEXT = 'kind-asterius-local'
NAMESPACE = 'asterius-playground'
ORIGIN = 'https://desktop-cpbptqn-1.tailacbb15.ts.net:8446'
APPS = {
    'demo-a': ('asterius_playground_demo_a', '/demo-a/login'),
    'demo-b': ('asterius_playground_demo_b', '/demo-b/login'),
    'financial-api': ('asterius_playground_financial', '/financial-api/auth/start'),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    raw = subprocess.check_output([
        'kubectl', '--context', CONTEXT, '-n', NAMESPACE, 'get',
        'deployment', *APPS, '-o', 'json',
    ], text=True)
    deployments = {d['metadata']['name']: d for d in json.loads(raw)['items']}
    opener = urllib.request.build_opener(NoRedirect())
    for path in ('/demo-a', '/demo-b', '/financial', '/financial-api', '/protocols'):
        try:
            response = opener.open(ORIGIN + path, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.code != 308 or response.headers.get('Location') != path + '/':
                raise RuntimeError(f'{path}: expected a relative slash redirect; HTTP {response.code}')
            if response.headers.get('Cache-Control') != 'no-store':
                raise RuntimeError(f'{path}: gateway allows cached slash redirects')
    with opener.open(ORIGIN + '/protocols/', timeout=15) as response:
        if response.headers.get_all('Referrer-Policy') != ['same-origin']:
            raise RuntimeError('Protocol page referrer policy suppresses native form origins')
    checked = []
    for name, (cookie_name, path) in APPS.items():
        deployment = deployments[name]
        env = deployment['spec']['template']['spec']['containers'][0]['env']
        configured = next((v.get('value') for v in env if v['name'] == 'COOKIE_NAME'), None)
        if configured != cookie_name:
            raise RuntimeError(f'{name}: deployed COOKIE_NAME does not match gateway contract')
        status = deployment.get('status', {})
        if (status.get('observedGeneration', 0) < deployment['metadata']['generation']
                or status.get('updatedReplicas') != 1
                or status.get('availableReplicas') != 1):
            raise RuntimeError(f'{name}: current deployment has not completed its rollout')
        try:
            response = opener.open(ORIGIN + path, timeout=15)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            if response.code not in (302, 303):
                raise RuntimeError(f'{name}: login handoff returned HTTP {response.code}')
            cookies = http.cookies.SimpleCookie()
            for header in response.headers.get_all('Set-Cookie', []):
                cookies.load(header)
            expected = cookie_name + '_login'
            if set(cookies) != {expected}:
                raise RuntimeError(f'{name}: actual login cookie does not match gateway contract')
            cookie = cookies[expected]
            if not cookie['secure'] or not cookie['httponly'] or cookie['samesite'].lower() != 'lax':
                raise RuntimeError(f'{name}: login cookie security attributes differ')
            checked.append({'app': name, 'cookie_name': expected, 'handoff_status': response.code})
    print(json.dumps({'deployed_cookie_contracts': checked,
                      'protocol_referrer_policy': 'same-origin', 'credentials_used': False}))


if __name__ == '__main__':
    main()
