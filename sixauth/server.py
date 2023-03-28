import socket
import asyncio
import threading
import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

def session(data):
    return data

class Client:
    def __init__(self, socket:socket.socket, f:Fernet, address):
        self.socket = socket
        self.f = f
        self.address = address
        self.dead = False
    
    def is_dead(self):
        return self.dead

    def send(self, data:dict):
        encrypted_data = self.f.encrypt(json.dumps({'code':321, 'data':data}).encode('utf-8'))
        first = self.f.encrypt(json.dumps({'code':320, 'len':len(encrypted_data)}).encode('utf-8'))
        self.socket.send(first)
        self.socket.send(encrypted_data)
        
    def recv(self):
        try:
            first = self.socket.recv(1024)
            if first == b'':
                return {'code':502}
            first = json.loads(self.f.decrypt(first))
            code = first.get('code')
            if not code:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            if code == 420:
                return {'code':500}
            if code == 400:
                return {'code':501}
            if code != 320:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            second = self.socket.recv(first['len'])
            if second == b'':
                return {'code':502}
            second = json.loads(self.f.decrypt(second))
            code = second.get('code')
            if code != 321:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                return {'code':500}
            return {'code':200, 'recv':second['data']}
        except InvalidToken:
            self.socket.send(json.dumps({'code':400}).encode('utf-8'))
            return {'code':500}

class Server:
    def __init__(self, host:str, port:int):
        self.stop_flag = threading.Event()
        self.session = session
        self.server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
        server_public_key = self.server_private_key.public_key()
        self.server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        try:
            asyncio.run(self.server_main_loop())
        except KeyboardInterrupt:
            pass
        except BaseException as err:
            pass
        finally:
            self.server_socket.close()
    
    async def server_main_loop(self):
        self.loop = asyncio.get_event_loop()
        self.clients = set()
        while not self.stop_flag.is_set():
            client_socket, client_address = await self.loop.sock_accept(self.server_socket)
            task = asyncio.create_task(self.setup_client(client_socket, client_address))
            self.clients.add(task)
            task.add_done_callback(self.clients.discard)
            
    async def setup_client(self, client_socket:socket.socket, client_address):
        client_public_key_bytes = await self.loop.sock_recv(client_socket, 1024)
        client_public_key = serialization.load_pem_public_key(
        client_public_key_bytes, default_backend())
        await self.loop.sock_sendall(client_socket, self.server_public_key_bytes)
        shared_secret = self.server_private_key.exchange(ec.ECDH(), client_public_key)
        kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"session key",
        backend=default_backend())
        key = kdf.derive(shared_secret)
        f = Fernet(base64.urlsafe_b64encode(key))
        client = Client(client_socket, f, client_address)
        await self.main_client_loop(client)
        client_socket.close()
        
    async def main_client_loop(self, client:Client):
        while not self.stop_flag.is_set() and not client.is_dead():
            try:
                status = self.run_client(client)
                if not status:
                    break
            except BaseException as err:
                client.send({'code':420, 'data':None, 'error':str(err)})
    
    def run_client(self, client):
        request = client.recv()
        if request['code'] == 502:
            return False
        if request['code'] == 500:
            return True
        if request['code'] == 501:
            # a 501 response from the recv function means that the sender reported that
            # it couldn't understand the previous response/send message.
            # meaning that instead of just waiting for another response from the client, like we are here,
            # we should attempt to send the pervious message again. (maybe with max retries?)
            return True  
        if request['recv']['code'] == 310:
            response = {'code':423}
        else:
            response = self.session(request['recv'])
        client.send(response)
        if request['recv']['code'] == 309 and response['code'] == 200:
            client.recv()
            client.send({'code':200})
            return False
