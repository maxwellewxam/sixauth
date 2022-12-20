import sys
import os
#HERE = os.path.abspath('../')
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth.auth_backend import start_server
start_server('127.0.0.1', 5678)