import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import AuthSesh as ash
hmm = ash()
hmm.set_vals('test', 'test')
print(hmm.login())