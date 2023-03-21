from classes import Cache, User, FrontSession
from cryptography.fernet import Fernet
import sys
import os
if sys.platform == 'win32':
    HERE = os.path.abspath('../maxmods/')
else:
    HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth import AuthSesh as ash

hmm = {'notcode': 'lol', 'code':300}

print(hmm.get('code'))
