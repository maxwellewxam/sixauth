import sys
import os
# if sys.platform == 'win32':
#     HERE = os.path.abspath('../')
# else:
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import backend_session

hmm = backend_session('127.0.0.1:5678')
print(hmm(amsdn='234234'))
