#client_logger.info('')
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import server2
server2()#'127.0.0.1', 5678, cache_threshold = 600)