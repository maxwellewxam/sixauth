import cProfile
import re
import dis
import sys
import os
sys.path.append('C:\\Users\\3008362\\AppData\\Local\\Programs\\Python\\Python311\\Lib\\maxmods')
    
def main():
    from sixauth import AuthSesh as ash
    with ash() as sesh:
        sesh.set_vals('name', 'pass')
        sesh.signup()
        sesh.login()
        sesh.save('rand/loc', 'what to put here')
        print(sesh.load('rand/loc'))
        sesh.delete('rand/loc')
        sesh.remove()
from sixauth.main import logger
logger.setup_logger(server_logger_location=None, log_more=True)
main()