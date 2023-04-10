import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
sys.path.append(HERE)
from sixauth.server import Server, logger
logger.setup_logger(client_logger_location=logger.server, log_sensitive = True, log_more = True)
Server('127.0.0.1', 5678, use_default_logger = False, cache_timeout=600)