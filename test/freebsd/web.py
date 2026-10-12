# Tiny HTTP server without http.server's startup DNS lookup.
import http.server, socketserver, sys

class Quiet(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("0.0.0.0", int(sys.argv[1])), Quiet).serve_forever()
