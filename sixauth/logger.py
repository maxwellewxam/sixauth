import logging
import os
import time

from . import logs

class Logger:
    def __init__(self, server_console: logging.Logger, client_console: logging.Logger, server_logger: logging.Logger, client_logger: logging.Logger, console_handler, formatter):
        self.server_console = server_console
        self.client_console = client_console
        self.client_logger = client_logger
        self.server_logger = server_logger
        self.console_handler = console_handler
        self.formatter = formatter
        self.server = 'this just needs to be a random variable, it could lowk be anything i could ever want'
    
    def set_logger(self, loghandle:logging.Logger):
        def log_func(text):
            loghandle.info(text)
        return log_func
    
    def setup_logger(self,
                        client_logger_location:str = os.path.dirname(logs.__file__), 
                        server_logger_location:str = None, 
                        debug:bool = False,
                        log_sensitive:bool = False,
                        log_more:bool = False):
        if client_logger_location == self.server:
            self.client_logger_location = server_logger_location
        else:
            self.client_logger_location = client_logger_location
        self.server_logger_location = server_logger_location
        self.debug = debug
        self.log_sensitive = log_sensitive
        self.log_more = log_more
        self.client_console.handlers = []
        self.client_logger.handlers = []
        self.server_console.handlers = []
        self.server_logger.handlers = []
        if server_logger_location != None:
            server_logger_handler = logging.FileHandler(server_logger_location+'/server.log')
            self.server_console.addHandler(server_logger_handler)
            self.server_logger.addHandler(server_logger_handler)
            self.server_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
            if self.log_sensitive:
                self.server_logger.info('WARNING: LOGGING SENSITIVE INFO')
            server_logger_handler.setFormatter(self.formatter)
        if client_logger_location != None:
            if client_logger_location == self.server:
                client_logger_handler = server_logger_handler
                self.client_console.addHandler(client_logger_handler)
                self.client_logger.addHandler(client_logger_handler)
                client_logger_handler.setFormatter(self.formatter)
            else:
                client_logger_handler = logging.FileHandler(client_logger_location+'/client.log')
                self.client_console.addHandler(client_logger_handler)
                self.client_logger.addHandler(client_logger_handler)
                self.client_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
                if self.log_sensitive:
                    self.client_logger.info('WARNING: LOGGING SENSITIVE INFO')
                client_logger_handler.setFormatter(self.formatter)
        self.server_console.addHandler(self.console_handler)
        self.client_console.addHandler(self.console_handler)
        return self
    
    def __call__(self, is_server = False, is_log_more=False, in_sensitive=False, out_sensitive=False, only_log_change=False):
        if is_server and self.debug:
            log = self.set_logger(self.server_console)
        elif is_server and not self.debug:
            log = self.set_logger(self.server_logger)
        elif not is_server and self.debug:
            log = self.set_logger(self.client_console)
        elif not is_server and not self.debug:
            log = self.set_logger(self.client_logger)
        
        def decorator(func):
            last_in = None
            last_out = None
            
            def wrapper(*args, **kwargs):
                nonlocal last_in
                nonlocal last_out
                if (is_log_more == False or self.log_more == True) and (not only_log_change or last_in != f'{args}{kwargs}'):
                    if not in_sensitive or self.log_sensitive:
                        log(f'{func.__name__} called with arguments {args} and {kwargs}')
                    else:
                        log(f'{func.__name__} called')
                last_in = f'{args}{kwargs}'
                start = time.time()               
                returned = func(*args, **kwargs)
                end = time.time()
                self.times.append((func.__name__, end-start, str(args), str(kwargs)))
                if (is_log_more == False or self.log_more == True) and (not only_log_change or last_out != f'{returned}'):
                    if not out_sensitive or self.log_sensitive:
                        log(f'{func.__name__} returned {returned}')
                    else:
                        log(f'{func.__name__} returned')
                if self.log_more and (not only_log_change or last_out != f'{returned}'):
                    log(f"{func.__name__} took {end-start} seconds to execute")
                last_out = f'{returned}'
                return returned
            return wrapper
        return decorator

server_console = logging.getLogger('server_console')
client_console = logging.getLogger('client_console')
server_logger = logging.getLogger('server_logger')
client_logger = logging.getLogger('client_logger')

server_console.setLevel(logging.INFO)
client_console.setLevel(logging.INFO)
server_logger.setLevel(logging.INFO)
client_logger.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = Logger(server_console, client_console, server_logger, client_logger, console_handler, formatter).setup_logger()
    
__all__ = ['logger', 'server_console', 'client_console', 'server_logger', 'client_logger']
