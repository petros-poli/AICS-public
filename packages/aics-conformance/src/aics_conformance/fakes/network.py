"""Loopback front ends for testing real urllib/socket/TLS clients."""
import threading
import socketserver
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
from .gate import exchange

@contextmanager
def http_server(fake):
    lock=threading.RLock()
    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            length=int(self.headers.get('Content-Length','0'))
            if length>1024*1024: self.send_error(413); return
            body=self.rfile.read(length) if length else None
            url='http://'+self.headers['Host']+self.path
            with lock: response=fake.request(self.command,url,body,dict(self.headers))
            self.send_response(response.status)
            for k,v in response.headers.items(): self.send_header(k,v)
            self.send_header('Content-Length',str(len(response.body))); self.end_headers(); self.wfile.write(response.body)
        do_GET=handle_request
        do_POST=handle_request
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try: yield f'http://127.0.0.1:{server.server_port}'
    finally: server.shutdown(); server.server_close(); thread.join(timeout=5)

@contextmanager
def tcp_server(fake, *, ssl_context=None):
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            text=exchange(fake,'POST',b'',{},plain=ssl_context is None)
            sid=text.splitlines()[0][8:]; self.wfile.write(text.encode()); self.wfile.flush()
            while True:
                line=self.rfile.readline(131074)
                if not line: return
                if line.rstrip()==b'sig-begin':
                    block=[line]
                    while block[-1].rstrip()!=b'sig-end':
                        part=self.rfile.readline(131074)
                        if not part: return
                        block.append(part)
                    line=b''.join(block)
                raw=('session '+sid+'\n').encode()+line
                text=exchange(fake,'POST',raw,{},plain=ssl_context is None)
                self.wfile.write(text.encode()); self.wfile.flush()
    server=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler); server.daemon_threads=True
    if ssl_context: server.socket=ssl_context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    try: yield f'localhost:{server.server_address[1]}'
    finally: server.shutdown(); server.server_close(); thread.join(timeout=5)
