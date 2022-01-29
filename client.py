import socket,dh,os
from Crypto.Util.number import long_to_bytes
from threading import Thread


file_save_directory = os.getcwd()+"/mailbox_files"
def socket_communication_file(payload, name):
    if not os.path.isdir(file_save_directory):
        os.mkdir(file_save_directory)

    file_name = f"{file_save_directory}/{name}_{os.urandom(10).hex()}"
    with open(file_name, "wb") as f:
        f.write(bytes.fromhex(payload))
    return f"File from {name} was saved at {file_name}"


def start_socket_communication(secret, sock):
    listen_conn, addr = sock.accept()
    with listen_conn:
        while True:
            try:
                data = dh.cipher_message(secret, listen_conn)
            except Exception as e:
                print(f"[SERVER DATA FETCH ERROR] {e}")
                print("Please restart the client.")
                os._exit(0)

            try:
                data_split = data.split("|", 2)
                payload_type = data_split[0]
                sender_name = data_split[1]
                payload = data_split[2]

                dispatch = {
                    "file": socket_communication_file,
                    "text": lambda payload,name: f"{name} said: {payload}"
                }
                print(dispatch[payload_type](payload, sender_name))
            except Exception as e:
                print(f"[SERVER DATA PARSING ERROR] {e} (Perhaps the data was corrupt?)")








## COMMANDS ##
def show_help():
    print("\nHELP")
    print("-"*20)
    print("Typing '!' before your message will mark your text as a command to be executed locally on your machine.")
    print("Prepending 'file:' before your message will mark your message as the name of a file to upload. (Ex: 'file:bruh' uploads the file 'bruh')")
    print("-"*20, end="\n\n")

def run_command(command):
    dispatch = {
        "help": show_help
    }

    try:
        dispatch[command]()
        return
    except KeyError:
        pass

    os.system(command)













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
        resp = dh.cipher_message(secret, parent_socket)
        if resp != "success":
            print(f"Error while signing up: {resp}")
            exit()

        print("-"*20, end="\n\n")
        print("Type somethin!")
        show_help()

        while True:
            data = input().strip()
            if data == "":
                continue

            payload_type = "text"
            if data.startswith("file:"):
                payload_type = "file"
                data = data[len("file:"):]
                if not os.path.isfile(data):
                    print(f"{data} is not a valid file.")
                    continue

                with open(data, "rb") as f:
                    data = f.read().hex()
            elif data.startswith("!"):
                try:
                    run_command(data[1:])
                except Exception as e:
                    print(f"Error during command execution: {e}")
                continue

            print("Sending..")
            dh.cipher_message(secret, parent_socket, f"{payload_type}|{data}")
            print(f"Result: {dh.cipher_message(secret, parent_socket)}")

def do_connect(ip):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(ip)
        print("Connection established! Awaiting P and G...")
        
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
        print(f"Connecting to {':'.join([str(segment) for segment in ip])}; hangon...")
        do_connect(ip)
    except ConnectionError as e:
        print(f"Connection error: {e}.")
        ip = None
    except Exception as e:
        print(f"Error happened: {e}")
