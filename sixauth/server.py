from .main import *
from .session import *

class Client:
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, socket:socket.socket, f:Fernet, address):
        self.socket = socket
        self.f = f
        self.address = address
        self.dead = False
    
    #@logger(is_log_more=True)
    def is_dead(self):
        if self.dead:
            server_console.info('I DIED')
        return self.dead

    @logger(is_log_more=True)
    def kill(self):
        self.dead = True
    
    @logger(is_log_more=True, in_sensitive=True)
    def send(self, data:dict):
        encrypted_data = self.f.encrypt(json.dumps({'code':321, 'data':data}).encode('utf-8'))
        first = self.f.encrypt(json.dumps({'code':320, 'len':len(encrypted_data)}).encode('utf-8'))
        self.socket.send(first)
        self.socket.send(encrypted_data)
        client_logger.info(f'Sent data to {self.address}')

    #@logger(is_log_more=True, out_sensitive=True)
    def recv(self):
        try:
            first = self.socket.recv(1024)
            if first == b'':
                return {'code':502}
            first = json.loads(self.f.decrypt(first))
            code = first.get('code')
            if not code:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                client_logger.info(f'{self.address} failed protocol')
                return {'code':500}
            if code == 420:
                client_logger.info(f'{self.address} sent 420')
                client_logger.info(f'{self.address} error: {first["error"]}')
                return {'code':500}
            if code == 400:
                client_logger.info(f'{self.address} sent protocol error')
                return {'code':501}
            if code != 320:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                client_logger.info(f'{self.address} failed protocol')
                return {'code':500}
            second = self.socket.recv(first['len'])
            if second == b'':
                return {'code':502}
            second = json.loads(self.f.decrypt(second))
            code = second.get('code')
            if code != 321:
                self.socket.send(self.f.encrypt(json.dumps({'code':400}).encode('utf-8')))
                client_logger.info(f'{self.address} failed protocol')
                return {'code':500}
            return {'code':200, 'recv':second['data']}
        except InvalidToken:
            self.socket.send(json.dumps({'code':400}).encode('utf-8'))
            client_logger.info(f'{self.address} used invalid token')
            return {'code':500}

class Server:
    @logger(is_log_more=True, is_server=True)
    def __init__(self, host:str, port:int, cache_timeout:int = 300, use_default_logger:bool = True, db_path:str = os.getcwd()):
        if use_default_logger:
            logger.setup_logger(client_logger_location=os.getcwd())
        if logger.log_sensitive:
            server_console.info('WARNING: Logging sensitive information')
        self.stop_flag = threading.Event()
        self.session = Session(is_server=True, cache_threshold=cache_timeout, path=db_path)
        self.server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
        server_public_key = self.server_private_key.public_key()
        self.server_public_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen()
        self.server_socket.setblocking(False)
        server_console.info(f'Server {VER} started')
        server_console.info('Press Ctrl+C to exit')
        server_console.info(f"Listening for incoming connections on {host}:{port}")
        try:
            asyncio.run(self.server_main_loop())
        except KeyboardInterrupt:
            server_console.info('Server Closed')
        except BaseException as err:
            server_console.info(f'Server did not exit successfully, Error: {err}')
        finally:
            self.server_socket.close()
            self.session(code=310)
    
    @logger(is_log_more=True, is_server=True)
    async def server_main_loop(self):
        self.loop = asyncio.get_event_loop()
        self.clients = set()
        while not self.stop_flag.is_set():
            client_socket, client_address = await self.loop.sock_accept(self.server_socket)
            task = asyncio.create_task(self.setup_client(client_socket, client_address))
            self.clients.add(task)
            task.add_done_callback(self.clients.discard)
    
    @logger(is_log_more=True, is_server=True, in_sensitive=True)
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
        server_console.info('client disconnected')
        client_socket.close()
    
    @logger(is_log_more=True, is_server=True)
    async def main_client_loop(self, client:Client):
        while not self.stop_flag.is_set() and not client.is_dead():
            try:
                status = self.run_client(client)
                if not status:
                    break
            except BlockingIOError:
                pass
            except BaseException as err:
                client.send({'code':420, 'data':None, 'error':str(err)})
                tb = traceback.extract_tb(sys.exc_info()[2])
                line_number = tb[-1][1]
                server_logger.info(f'Request processing for {client.address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}\n{str(tb)}')
    
    #@logger(is_log_more=True, is_server=True)
    def run_client(self, client:Client):
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
        request['recv']['client'] = client
        if request['recv']['code'] == 310:
            response = {'code':423}
        else:
            response = self.session(**request['recv'])
        client.send(response)
        if request['recv']['code'] == 309 and response['code'] == 200:
            client.recv()
            client.send({'code':200})
            return False
        return True

__all__ = ['Server', 'Client']
