import threading
from maxmods.auth.imports import *

def start_server(host, port):
    session = frontend_session()
    #Generate an ECDH key pair for the server
    server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()

    #Serialize the server's public key
    server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen()

    print(f"Listening for incoming connections on {host}:{port}...")

    def handle_client(client_socket, f, client_address, session):
    # Do something with the client's socket, such as send and receive data
        while True:
            recv = client_socket.recv(1024)
            if recv != None:
                data = json.loads(f.decrypt(recv).decode())
                if data['func'] == 'end_session':
                    end = session(**data)
                    client_socket.send(f.encrypt(json.dumps(end).encode('utf-8')))
                    if end['code'] == 200:
                        break
                print(f"Received data from client: {client_address}")
                client_socket.send(f.encrypt(json.dumps(session(**data)).encode('utf-8')))
            else:
                break
        print(f"Closed connection from {client_address}")
        client_socket.close()

    #Accept an incoming connection
    while True:
        client_socket, client_address = server_socket.accept()

        #Wait for the client's public key
        client_public_key_bytes = client_socket.recv(1024)

        #Deserialize the client's public key
        client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes, default_backend()
        )

        #Send the server's public key to the client
        client_socket.send(server_public_key_bytes)

        #Calculate the shared secret key using ECDH
        shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

        #Use HKDF to derive a symmetric key from the shared secret
        kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session key",
        backend=default_backend()
        )
        key = kdf.derive(shared_secret)

        #Use the symmetric key to encrypt and decrypt messages
        f = Fernet(base64.urlsafe_b64encode(key))

        print(f"Received incoming connection from {client_address}")
        
        # Create a new thread to handle the incoming connection
        client_thread = threading.Thread(target=handle_client, args=(client_socket,f, client_address, session))
        client_thread.start()