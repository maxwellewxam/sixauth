from .main import *
from .session import *

class Client:
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, socket:socket.socket, f:Fernet, address):
        self.socket = socket
        self.f = f
        self.address = address
        self.dead = False
        self.queue = queue.Queue()
    
    @logger(is_log_more=True, only_log_change=True)
    def is_dead(self):
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

    @logger(is_log_more=True, out_sensitive=True, only_log_change=True)
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
            time.sleep(0.01)
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
            return {'code':503}
        except BlockingIOError:
            return {'code':503}
        except TimeoutError:
            return {'code':503}

class Server:
    @logger(is_log_more=True, is_server=True)
    def __init__(self, host:str, port:int, cache_timeout:int = 300, use_default_logger:bool = True, db_path:str = os.getcwd()):
        if use_default_logger:
            logger.setup_logger(client_logger_location=logger.server, server_logger_location=os.getcwd())
        if logger.log_sensitive:
            server_console.info('WARNING: Logging sensitive information')
        self.clients = set()
        self.session = Session(is_server=True, cache_threshold=cache_timeout, path=db_path)
        self.stop_flag = self.session.cache.stop_flag
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
            main_thread = threading.Thread(target=self.run_thread)
            main_thread.start()
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            server_console.info('Server Closing')
        except BaseException as err:
            server_console.info(f'Server did not exit successfully, Error: {err}')
        finally:
            server_console.info('Press Ctrl+C to skip client closing')
            try:
                for key in list(self.session.cache.cache):
                    self.session.cache.cache[key]['done'](key)
                while self.clients:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
            server_console.info('Finished')
            self.session(code=310)
            self.server_socket.close()
            main_thread.join()
            server_console.info('Server closed')
    
    def run_thread(self):
        asyncio.run(self.server_main_loop())
    
    @logger(is_log_more=True, is_server=True)
    async def server_main_loop(self):
        self.loop = asyncio.get_event_loop()
        while not self.stop_flag.is_set():
            try:
                client_socket, client_address = self.server_socket.accept()
                task = asyncio.ensure_future(self.setup_client(client_socket, client_address))
                self.clients.add(task)
                task.add_done_callback(self.clients.discard)
            except BlockingIOError:
                 pass
            
    @logger(is_log_more=True, is_server=True, in_sensitive=True)
    async def setup_client(self, client_socket:socket.socket, client_address):
        try:
            client_public_key_bytes = client_socket.recv(1024)
            client_public_key = serialization.load_pem_public_key(
            client_public_key_bytes, default_backend())
            client_socket.send(self.server_public_key_bytes)
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
            self.main_client_loop(client)
            client_socket.close()
        except ConnectionResetError:
            pass
    
    @logger(is_log_more=True, is_server=True)
    def main_client_loop(self, client:Client):
        while not self.stop_flag.is_set() and not client.is_dead():
            try:
                self.check_client(client)
                status = self.run_client(client)
                if not status:
                    break
            except ConnectionResetError:
                pass
            except BaseException as err:
                try:
                    client.send({'code':420, 'data':None, 'error':str(err)})
                except:
                    pass
                tb = traceback.extract_tb(sys.exc_info()[2])
                line_number = tb[-1][1]
                server_logger.info(f'Request processing for {client.address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}\n{str(tb)}')
            #time.sleep(1)
    
    @logger(is_log_more=True, is_server=True, only_log_change=True)
    def check_client(self, client:Client):
        try:
            kill_call = client.queue.get(block=False)
            kill_call('kill called')
            return True
        except queue.Empty:
            return False
    
    @logger(is_log_more=True, is_server=True, only_log_change=True)
    def run_client(self, client:Client):
        request = client.recv()
        if request['code'] == 502:
            return False
        if request['code'] == 500:
            return True
        if request['code'] == 503:
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
