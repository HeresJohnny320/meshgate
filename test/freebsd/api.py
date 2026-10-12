# Minimal client for the meshgate local API over its unix socket.
#   python3 api.py <socket> <op> [json-body]
import http.client, json, socket, sys

class UnixConn(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("meshgate")
        self.path = path
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)

c = UnixConn(sys.argv[1])
if len(sys.argv) > 3:
    c.request("POST", "/v1/" + sys.argv[2], body=sys.argv[3], headers={"Content-Type": "application/json"})
else:
    c.request("GET", "/v1/" + sys.argv[2])
r = c.getresponse()
body = r.read().decode()
print(body)
sys.exit(0 if r.status == 200 else 1)
