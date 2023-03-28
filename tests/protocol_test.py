import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../')
sys.path.append(HERE)
from sixauth.server import Server
Server('127.0.0.1', 5678)