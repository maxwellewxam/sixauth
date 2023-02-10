import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth import AuthSesh
#from sixauth.main import logger
#logger.setup_logger(log_sensitive=True, log_more=True, server_logger_location=None)
with AuthSesh() as sesh:
    sesh.set_vals('max', 'max')
    sesh.signup()
    sesh.terminate()
    sesh.login()

# import json

# with open('C:/Users/3008362/AppData/Local/Programs/Python/Python311/Lib/MaxMods/tests/times.json', 'r') as file:

#     data = json.load(file)

# sorted_data = sorted(data, key=lambda x: x[1])

# print(sorted_data)

# for data in sorted_data:
#     print(data)
