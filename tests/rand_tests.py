import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import *

with AuthSesh() as auth:
    auth.set_vals('max', 'max')
    auth.login()
    
from maxmods.auth.auth_backend.cert_maker import make_certificates
make_certificates(use_cwd=False)