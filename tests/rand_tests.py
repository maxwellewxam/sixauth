import sys
import os
import json
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.client import establish_client_connection
from sixauth.server import Client

def send(cl:Client):
    cl.send(json.loads(input('dict: ')))
    print(cl.recv())
    
f, client_socket = establish_client_connection('127.0.0.1:5679')
cl = Client(client_socket, f, ('127.0.0.1', 5679))
while True:
    send(cl)