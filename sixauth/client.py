from .main2 import *
from .server import *

@logger(is_log_more=True)
def establish_client_connection(address:str):
    client_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket = socket.socket()
    connection_info = address.split(':')
    client_socket.connect((connection_info[0], int(connection_info[1])))
    client_socket.send(client_public_key_bytes)
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes, default_backend())
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend())
    key = kdf.derive(shared_secret)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f, client_socket

@logger()
def backend_session(address:str):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    client = Client(client_socket, f, address)
    client.socket.settimeout(30)
    
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data:dict):
        while True:
            client.send(data)
            recv = client.recv()
            if recv['code'] == 200:
                break
        return recv['recv']
    return session

__all__ = ['backend_session', 'establish_client_connection']
