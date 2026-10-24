#!/usr/bin/env python3
"""Serve only a fixed LAN test page for at most 15 minutes; no file access."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import time

BODY = b'<!doctype html><meta charset="utf-8"><title>HK6 LAB</title><h1>HK6-LAB: collegamento locale OK</h1><p>Questa pagina arriva dal Mac, senza Internet.</p>'
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != '/':
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(BODY)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(BODY)
        print('LAN check served to ' + self.client_address[0], flush=True)
    def log_message(self, *_):
        pass
if __name__ == '__main__':
    server = HTTPServer(('192.168.2.1', 8765), Handler)
    server.timeout = 1
    print('Ready: http://192.168.2.1:8765 (15 minute limit)', flush=True)
    deadline = time.monotonic() + 900
    try:
        while time.monotonic() < deadline:
            server.handle_request()
    finally:
        server.server_close()
