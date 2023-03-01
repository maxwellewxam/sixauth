from classes import Cache, User, FrontSession
from cryptography.fernet import Fernet
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import frontend_session, backend_session


id = Fernet.generate_key().hex()

#sesh = backend_session('127.0.0.1:5678')
sesh = FrontSession()
hash = sesh(code=301, id=id)['hash']
print(hash)
print(sesh(code=302, id=id, hash=hash, username='max', password='test')['code'])
print(sesh(code=307, id=id, hash=hash, username='max', password='test')['code'])
print(sesh(code=309, id=id, hash=hash)['code'])
print(sesh(code=310)['code'])