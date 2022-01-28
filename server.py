from socketserver import BaseRequestHandler, ThreadingTCPServer
from Crypto.Util.number import long_to_bytes
import dh, socket, string

connections = []
def send_to_all(msg):
    for i,connection in enumerate(connections):
        secret, socket = connection
        try:
            dh.cipher_message(secret, socket, msg)
        except ConnectionError:
            del connections[i]
            pass

def sanitize(text):
    new_txt = ""
    for char in text:
        for good_char in " "+string.ascii_letters+string.digits+string.punctuation:
            if char == good_char:
                new_txt += char
    return new_txt

class Handler(BaseRequestHandler):
    def handle(self):
        print("Connection began")
        print("Generating P and G...")

        p,g = dh.calculate_shared_variables()
        self.request.send(f"{p}|{g}".encode("ascii"))
        print("P and G sent")

        client_public = dh.receive_public_key(self.request)
        private = dh.generate_keys(g,p,self.request)
        secret = long_to_bytes(pow(client_public, private, p))
        print(f"{secret=}")
        port = int(dh.cipher_message(secret, self.request))
        name = dh.cipher_message(secret, self.request)

        rpc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rpc_sock.connect((self.client_address[0], port))

        connections.append((secret, rpc_sock))
        print(f"{self.client_address[0]}:{port} connected")
        print(f"There are currently {len(connections)} connections.")

        print("-"*20,end="\n\n")
        while True:
            received_msg = dh.cipher_message(secret, self.request).strip()
            send_to_all(sanitize(f"{name} said: {received_msg}"))

def start_server():
    with ThreadingTCPServer(("0.0.0.0", 5555), Handler) as server:
        print(f"Starting TCP server on port {server.socket.getsockname()[1]}")

        server.allow_reuse_address = 1
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            send_to_all("The server is shutting down.")
            print("Stopping..")
        except Exception as e:
            print(f"Uh oh, exception: {e}")

def start():
    try:
        start_server()
    except OSError:
        start()
start()