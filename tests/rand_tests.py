import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import *
from maxmods.auth.imports import *

hmm = backend_session('127.0.0.1:5678')
id = Fernet.generate_key().hex()
hash = hmm(func='create_session', id=id)['hash']
hmm(func='end_session', id=id, hash=hash)
# hmm = AuthSesh(Address='127.0.0.1:5678')
