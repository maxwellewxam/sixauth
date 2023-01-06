
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth.main import server
server('127.0.0.1', 5678, log_senseitive_info = True, cache_threshold = 5)