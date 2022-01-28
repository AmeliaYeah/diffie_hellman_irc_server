import socket,dh,os
from Crypto.Util.number import long_to_bytes
from threading import Thread

def start_socket_communication(secret, sock):
    listen_conn, addr = sock.accept()
    with listen_conn:
        while True:
            try:
                print(f"[SERVER] {dh.cipher_message(secret, listen_conn)}")
            except Exception as e:
                print(f"[SERVER DATA FETCH ERROR] {e}")
                print("Please restart the client.")
                os._exit(0)

def start_listening_socket(secret, parent_socket):
    global socket_started
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as child_sock:
        child_sock.bind(("0.0.0.0", 0))
        child_sock.listen()
        port = child_sock.getsockname()[1]

        print(f"Listening socket is listening on {port=}")
        dh.cipher_message(secret, parent_socket, str(port))
        Thread(target=start_socket_communication, args=(secret, child_sock)).start()

        dh.cipher_message(secret, parent_socket, input("Type your nickname: ").strip())
        print("-"*20, end="\n\n")
        print("Type somethin!")
        while True:
            data = input().strip()
            if data == "":
                continue
            dh.cipher_message(secret, parent_socket, data)

def do_connect(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(ip)
        data = sock.recv(4096).decode("ascii").split("|")
        shared = {}
        for index,variable in enumerate(["p", "g"]):
            shared[variable] = int(data[index])
            print(f"Shared variable {variable} is {shared[variable]}")

        private = dh.generate_keys(shared["g"], shared["p"], sock)
        server_public = dh.receive_public_key(sock)
        secret = long_to_bytes(pow(server_public, private, shared["p"]))
        print(f"{secret=}")
        
        start_listening_socket(secret, sock)

ip = None
while True:
    if ip == None:
        try:
            _ip = input("Enter an IP address to connect to: ").strip()

            ip = (_ip,5555)
        except Exception as e:
            print(f"Error: {e}")
            continue

    try:
        do_connect(ip)
    except ConnectionError as e:
        print(f"Connection error: {e}.")
        ip = None
    except Exception as e:
        print(f"Error happened: {e}")