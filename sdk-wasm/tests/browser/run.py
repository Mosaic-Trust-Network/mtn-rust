"""Run the local SDK browser gate in an isolated Chrome profile."""
import functools,html,http.server,json,pathlib,re,shutil,subprocess,tempfile,threading,urllib.parse
root=pathlib.Path(__file__).resolve().parents[2]
class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        path=urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if ".." in path.split("/") or not path.startswith(("/tests/browser/","/tests/vectors/","/dist/","/generated/web/")):
            self.send_error(404);return
        super().do_GET()
    def end_headers(self):
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'")
        super().end_headers()
    def log_message(self,*args): pass
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(Handler,directory=str(root)))
threading.Thread(target=server.serve_forever,daemon=True).start()
try:
    with tempfile.TemporaryDirectory(prefix='tresor-browser-') as profile:
        chrome=shutil.which('google-chrome') or shutil.which('chromium')
        if not chrome: raise RuntimeError('Chrome/Chromium is required for this browser gate')
        url=f'http://127.0.0.1:{server.server_port}/tests/browser/index.html'
        args=[chrome,'--headless','--disable-gpu','--disable-background-networking','--disable-component-update','--no-first-run',f'--user-data-dir={profile}','--virtual-time-budget=10000','--dump-dom',url]
        process=subprocess.run(args,capture_output=True,text=True,timeout=40)
        match=re.search(r'<pre id="result">(.*?)</pre>',process.stdout,re.S)
        if process.returncode or not match: raise RuntimeError(f'Browser failed: exit {process.returncode}; {process.stderr[-1500:]}')
        outcome=json.loads(html.unescape(match.group(1)))
        print(json.dumps(outcome,indent=2))
        if not outcome.get('complete') or outcome.get('fail')!=0: raise SystemExit(1)
finally: server.shutdown();server.server_close()
