import sys
import os
import time
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import AuthSesh

ash = AuthSesh('127.0.0.1:5678')
ash.set_vals('max', 'max')
#ash.signup()
ash.login()
ash.save('','sensitive data')
time.sleep(10)
print(ash.load())
ash.remove()
ash.terminate()