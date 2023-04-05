#client_logger.info('')
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
sys.path.append(HERE)
from sixauth.server import *
from sixauth.main import *
logger.setup_logger(client_logger_location=os.getcwd(), log_sensitive = True, log_more = True)

class NewServer(Server):
    @logger(is_log_more=True, is_server=True)
    async def server_main_loop(self):
        self.loop = asyncio.get_event_loop()
        self.clients = set()
        self.new_socket = socket.socket()
        self.new_socket.connect(('127.0.0.1', 5678))
        while not self.stop_flag.is_set():
            client_socket, client_address = await self.loop.sock_accept(self.server_socket)
            task1 = asyncio.create_task(self.send_client(client_socket))
            task2 = asyncio.create_task(self.send_server(client_socket))
            self.clients.add(task1)
            self.clients.add(task2)
            task1.add_done_callback(self.clients.discard)
            task2.add_done_callback(self.clients.discard)
    
    @logger(is_log_more=True, is_server=True, in_sensitive=True)
    async def send_client(self, client_socket:socket.socket):
        while not self.stop_flag.is_set():
            data = await self.loop.sock_recv(client_socket, 1024)
            print(f'client sent "{data}" to the server')
            await self.loop.sock_sendall(self.new_socket, data)
    
    @logger(is_log_more=True, is_server=True, in_sensitive=True)
    async def send_server(self, client_socket:socket.socket):
        while not self.stop_flag.is_set():
            data = await self.loop.sock_recv(self.new_socket, 1024)
            print(f'server sent "{data}" to the client')
            await self.loop.sock_sendall(client_socket, data)


NewServer('127.0.0.1', 5679, use_default_logger = False)
