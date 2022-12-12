import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth.imports.auth_function import *

class authtest:
    def __init__(self):
        self.sesh = Session()
        self.id = Fernet.generate_key().hex()
        self.hash = greet(self.sesh, Id = self.id)['Hash']
    def handle(self, request):
        if request['Code'] == 200:
            return True
        
        elif request['Code'] == 401:
            raise PasswordError('Incorrect password')
        
        elif request['Code'] == 404:
            raise UsernameError('Username does not exist')
        
        elif request['Code'] == 406:
            raise UsernameError('Invalid username')
        
        elif request['Code'] == 409:
            raise UsernameError('Username already exists')
        
        elif request['Code'] == 423:
            raise AuthenticationError('Failed to authenticate user')

    def login(self, username, password):
        return self.handle(login(self.sesh, Username=username, Password=password, Id=self.id, Hash=self.hash))
    def signup(self, username, password):
        return self.handle(signup(self.sesh, Username=username, Password=password))
    
hmm = authtest()
hmm.signup('tes1t', 'test')
print(hmm.login('test', 'test'))
hmm.login('g','g')    
