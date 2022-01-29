from socketserver import BaseRequestHandler, ThreadingTCPServer
from Crypto.Util.number import long_to_bytes
import dh, socket, string

connections = []
def send_to_all(msg, exclude_user=None):
    for i,connection in enumerate(connections):
        secret, socket, name = connection
        if name == exclude_user:
            continue
        try:
            dh.cipher_message(secret, socket, msg)
        except ConnectionError:
            del connections[i]
            pass

def check_name_exists(name):
    for connection in connections:
        secret, socket, current_name = connection
        if current_name == name:
            return True

    return False



### Sanitization Functions ###
def sanitize_file(hex):
    try:
        bytes.fromhex(hex)
    except ValueError:
        raise "You can only supply valid hexadecimal for the file payload!"
        
    return hex


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
        user_msg = lambda message=None: dh.cipher_message(secret, self.request, message)

        port = int(user_msg())
        name = user_msg()
        if check_name_exists(name):
            user_msg("Name exists")
            self.request.close()
        else:
            user_msg("success")

        rpc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rpc_sock.connect((self.client_address[0], port))

        connections.append((secret, rpc_sock, name))
        print(f"{self.client_address[0]}:{port} connected")
        print(f"There are currently {len(connections)} connections.")

        print("-"*20,end="\n\n")
        while True:
            received_msg = user_msg().strip()
            try:
                split_payload = received_msg.split("|", 1)
                payload_type = split_payload[0]
                payload = split_payload[1]

                dispatch = {
                    "file": (sanitize_file, True, "hex"),
                    "text": (sanitize, False, "ascii")
                }
                dispatch_res, hide_text, text_fmt = dispatch[payload_type]
                requested = f"({len(payload)} bytes)"
                if not hide_text:
                    requested = f"\"{payload}\""
                    
                print(f"{name} requested payload {payload_type}: {requested} (in {text_fmt})")
                send_to_all(payload_type+"|"+name+"|"+dispatch_res(), exclude_user=name)
            except Exception as e:
                user_msg(f"[FAILURE] {e}")
                continue

            user_msg("Successfully sent")

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
