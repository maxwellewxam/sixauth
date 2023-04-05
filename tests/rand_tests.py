import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
sys.path.append(HERE)
from sixauth import AuthSesh
from sixauth.main import logger, time
logger.setup_logger(log_sensitive = True, log_more = True)

sesh = AuthSesh('127.0.0.1:5678')

sesh.set_vals('max', 'max')
sesh.signup()
sesh.login()
sesh.save('home/babe', 'MOMMMY')
print(sesh.load('home/babe'))
time.sleep(10)
print(sesh.load())