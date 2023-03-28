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
from sixauth.server import Client

@logger()
def backend_session(address:str):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    server = Client(client_socket, f, address)
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data:dict):
        try:
            server.send(data)
        except:
            pass
        return server.recv()
    return session
    
server = backend_session('127.0.0.1:5678')
while True:
    send = int(input('code: '))
    print(server(code=send))