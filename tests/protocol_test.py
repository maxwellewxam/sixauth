import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
sys.path.append(HERE)
from sixauth.main import Server, logger, Connection, server_logger
class NewServer(Server):
    async def main_client_loop(self, client_socket, client_address, f):
        client = Connection(client_socket, client_address, f, server_logger)
        while not self.stop_flag1.is_set() and not client.is_dead():
            recv = client.recv()
            if recv.get('code') == 200:
                client.send({'code':200, 'your data': recv.get('recv')})
                if recv['recv']['code'] == 100:
                    client.dead = True
            if recv.get('code') == 502:
                client.dead = True

logger.setup_logger(client_logger_location=os.getcwd(), log_sensitive = True, log_more = True)
NewServer('127.0.0.1', 5678, cache_threshold = 600, use_default_logger = False)