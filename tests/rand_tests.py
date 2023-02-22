import cProfile
import re
import os
import sys
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
sys.path.reverse()
from sixauth import AuthSesh as ash



with ash('127.0.0.1:5678')as sesh:
    sesh.set_vals('max', 'max')
    #sesh.signup()
    sesh.login()
    sesh.save('f1/f2/f3', ['maxwellewxam'] * 6000)
    print(sesh.load('f1/f2/f3'))
    #sesh.remove()
    