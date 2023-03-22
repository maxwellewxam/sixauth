from classes import Cache, User, FrontSession
from cryptography.fernet import Fernet
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import *

@logger()
def backend_session(address:str):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    server = Connection(client_socket, address, f, client_logger)
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data:dict):
        server.send(data)
        return server.recv()
    return session
    
server = backend_session('127.0.0.1:5678')
while True:
    send = int(input('code: '))
    print(server(code=send))