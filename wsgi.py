#!/usr/bin/env python3
"""
WSGI Application adapter for Ivris Social Platform.
Optimized for 24/7 unmetered production hosting on PythonAnywhere.
"""
import io
import os
import sys
from pathlib import Path

# Ensure repository root is on sys.path
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

# Import server components
from server import IvrisHandler, init_db

# Initialize database schema and migrations on startup
init_db()


class WSGISocket:
    """Mock socket implementing rfile / wfile streams for SimpleHTTPRequestHandler under WSGI."""
    def __init__(self, rbytes: bytes):
        self.rfile = io.BytesIO(rbytes)
        self.wfile = io.BytesIO()

    def makefile(self, mode: str, *args, **kwargs):
        if 'r' in mode:
            return self.rfile
        elif 'w' in mode:
            return self.wfile
        raise ValueError(mode)

    def sendall(self, data: bytes):
        self.wfile.write(data)


class WSGIDummyServer:
    server_name = 'pythonanywhere'
    server_port = 443


def application(environ, start_response):
    """
    Standard WSGI entrypoint callable.
    Compatible with uWSGI, Gunicorn, and PythonAnywhere.
    """
    method = environ.get('REQUEST_METHOD', 'GET')
    path = environ.get('PATH_INFO', '/')
    query = environ.get('QUERY_STRING', '')
    if query:
        path = f'{path}?{query}'

    # Reconstruct raw HTTP/1.1 request lines for BaseHTTPRequestHandler
    req_lines = [f'{method} {path} HTTP/1.1']

    content_length = environ.get('CONTENT_LENGTH')
    if content_length:
        req_lines.append(f'Content-Length: {content_length}')

    content_type = environ.get('CONTENT_TYPE')
    if content_type:
        req_lines.append(f'Content-Type: {content_type}')

    for k, v in environ.items():
        if k.startswith('HTTP_'):
            header_name = k[5:].replace('_', '-').title()
            req_lines.append(f'{header_name}: {v}')

    header_bytes = ('\r\n'.join(req_lines) + '\r\n\r\n').encode('latin-1')

    body = b''
    if content_length:
        try:
            cl_int = int(content_length)
            if cl_int > 0:
                body = environ['wsgi.input'].read(cl_int)
        except Exception:
            pass

    raw_request = header_bytes + body
    sock = WSGISocket(raw_request)

    client_ip = environ.get('REMOTE_ADDR', '127.0.0.1')
    try:
        client_port = int(environ.get('REMOTE_PORT', 8080) or 8080)
    except Exception:
        client_port = 8080

    try:
        IvrisHandler(sock, (client_ip, client_port), WSGIDummyServer())
        raw_response = sock.wfile.getvalue()

        header_end = raw_response.find(b'\r\n\r\n')
        if header_end == -1:
            start_response('500 Internal Server Error', [('Content-Type', 'text/plain')])
            return [b'500 Internal Server Error: Missing header boundary']

        head_part = raw_response[:header_end].decode('latin-1')
        body_part = raw_response[header_end + 4:]

        lines = head_part.split('\r\n')
        status_line = lines[0]
        status_tokens = status_line.split(' ')
        status = ' '.join(status_tokens[1:]) if len(status_tokens) > 1 else '200 OK'

        resp_headers = []
        for line in lines[1:]:
            if ': ' in line:
                hn, hv = line.split(': ', 1)
                # Filter out hop-by-hop headers
                if hn.lower() in ('connection', 'keep-alive'):
                    continue
                resp_headers.append((hn, hv))

        start_response(status, resp_headers)
        return [body_part]
    except Exception as e:
        err_msg = f'500 Internal Server Error: {e}\n'.encode('utf-8')
        start_response(
            '500 Internal Server Error',
            [
                ('Content-Type', 'text/plain; charset=utf-8'),
                ('Content-Length', str(len(err_msg))),
            ],
        )
        return [err_msg]


if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    port = int(os.environ.get('PORT', 8000))
    print(f'Starting WSGI server on port {port}...')
    with make_server('0.0.0.0', port, application) as httpd:
        httpd.serve_forever()
