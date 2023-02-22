#client_logger.info('')
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import server, logger
#logger.setup_logger(client_logger_location=os.getcwd(), log_sensitive = True, log_more = True)
server('127.0.0.1', 5678, cache_threshold = 600)#, use_default_logger = False)
