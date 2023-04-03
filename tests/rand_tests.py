import sys
import os
import json
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import establish_client_connection
from sixauth.server import Client

def send(f, client_socket):
    code = json.loads(input('code: '))
    client_socket.send(f.encrypt(json.dumps(code).encode('utf-8')))
    try:
        data = json.loads(f.decrypt(client_socket.recv(1024)))
        print(data)
    except KeyboardInterrupt:
        return
    
f, client_socket = establish_client_connection('127.0.0.1:5678')
while True:
    send(f, client_socket)