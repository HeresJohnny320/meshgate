# Tiny "game server": tells each client which source address it sees.
import socket, sys, threading

def serve(c, addr):
    with c:
        c.settimeout(3)
        try:
            c.sendall(("hello from game server, you are %s\n" % addr[0]).encode())
            # Closing with unread input (the "\n" from `echo | nc`) makes the
            # kernel send RST, and netcat-openbsd then drops our reply. Send
            # FIN instead and drain until the client hangs up.
            c.shutdown(socket.SHUT_WR)
            while c.recv(4096):
                pass
        except OSError:
            pass

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", int(sys.argv[1])))
s.listen()
while True:
    c, addr = s.accept()
    threading.Thread(target=serve, args=(c, addr), daemon=True).start()
