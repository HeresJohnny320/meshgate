# Tiny "game server": tells each client which source address it sees.
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen()
while True:
    c, addr = s.accept()
    c.sendall(("hello from game server, you are %s\n" % addr[0]).encode())
    c.close()
