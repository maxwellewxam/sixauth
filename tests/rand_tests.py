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

user1 = ash('127.0.0.1:5678')
user1.set_vals('max', 'test')
user1.login()
#user1.save('some/place/23', 'NO WAY WE CAN SAVE IF THE USER DOESNT FUCKING DO IT')
print(user1.load('some/place/23'))
