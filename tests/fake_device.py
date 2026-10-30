import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


class FakeDevice:
    """Минимальная реализация контракта core_fs + otaclient для тестов сервера."""

    def __init__(self, port=18081, versionfs="V1"):
        self.port = port
        self.versionfs = versionfs
        self.files = {
            "/config_sys.json": b'{"name":"esp32"}',
            "/secret.json": b'{"auth":false,"user":"admin","password":""}',
            "/macros/a.lua": b'print("a")',
            "/style.css": b"body{}",
            "/_version_fs.json": b'{"version":"V1"}',
        }
        self.dirs = {"/macros"}
        self.restart_count = 0
        self.test_code = 0
        self.test_name = ""
        self.fs_update_available = True
        self.fs_updated = False
        self._server = None
        self._thread = None

    # ---- lifecycle ----
    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, code, body=b"", content_type="text/plain"):
                self.send_response(code)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                u = urlparse(self.path)
                path = u.path
                if path == "/system/version":
                    body = (f"devicename|Electronica|div\n"
                            f"deviceserial|D003|div\n"
                            f"versionapp|1.0|div\n"
                            f"versionfs|{outer.versionfs}|div\n"
                            f"buildenv|esp32_electronica7_rgb_macros|div\n")
                    return self._send(200, body.encode())
                if path == "/fs/info":
                    used = sum(len(v) for v in outer.files.values())
                    body = json.dumps({
                        "api": 1, "fsType": "littlefs", "total": 1048576,
                        "used": used, "free": 1048576 - used, "usedPct": 1,
                        "blockSize": 4096, "maxUpload": 1048576,
                        "fsVersion": outer.versionfs, "buildEnv": "test",
                    }).encode()
                    return self._send(200, body, "application/json")
                if path == "/fs/list":
                    entries = []
                    for d in sorted(outer.dirs):
                        if d != "/":
                            entries.append({"path": d, "type": "dir", "size": 0, "mtime": 0})
                    for p, data in sorted(outer.files.items()):
                        entries.append({"path": p, "type": "file",
                                        "size": len(data), "mtime": 0})
                    body = json.dumps({"count": len(entries), "truncated": False,
                                       "entries": entries}).encode()
                    return self._send(200, body, "application/json")
                if path == "/fs/download":
                    p = parse_qs(u.query).get("path", [""])[0]
                    if p not in outer.files:
                        return self._send(404, b"not found")
                    return self._send(200, outer.files[p],
                                      "application/octet-stream")
                if path == "/otaclient/teststatus":
                    name = outer.test_name
                    if outer.test_code == 4 and not name:
                        name = "Electronica-FILESYS-1.2.3.bin"
                    body = json.dumps({"code": outer.test_code, "name": name}).encode()
                    return self._send(200, body, "application/json")
                return self._send(404, b"not found")

            def do_POST(self):
                u = urlparse(self.path)
                path = u.path
                length = int(self.headers.get("Content-Length") or 0)
                data = self.rfile.read(length) if length else b""
                if path == "/fs/upload":
                    p = parse_qs(u.query).get("path", [""])[0]
                    if not p.startswith("/"):
                        return self._send(400, b"bad path")
                    outer.files[p] = data
                    return self._send(200, b"OK")
                if path == "/system/restart":
                    outer.restart_count += 1
                    return self._send(200, b"OK")
                if path == "/otaclient/test":
                    outer.test_code = 4 if outer.fs_update_available else 3
                    outer.test_name = "Electronica-FILESYS-1.2.3.bin"
                    return self._send(200, b"OK")
                if path == "/otaclient/update":
                    if outer.test_code == 4:
                        outer.versionfs = "V2"
                        outer.fs_updated = True
                    return self._send(200, b"OK")
                return self._send(404, b"not found")

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
