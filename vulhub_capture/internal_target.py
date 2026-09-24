import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def _send(self, body):
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("X-Internal-Service","metadata-v1")
        self.end_headers()
        self.wfile.write(body.encode())
    def do_GET(self):
        # emulate an internal metadata endpoint (attacker's SSRF target)
        self._send(json.dumps({"iam":{"role":"internal-svc"},"secret_token":"INTERNAL-DEMO-TOKEN-abc123","private_ip":"10.0.0.5"}))
    def do_POST(self): self.do_GET()
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",9999),H).serve_forever()
