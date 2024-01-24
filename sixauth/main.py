# Made with love by Max
import machineid

VER = '1.1.0_DEV.1'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here

# first we need a database connection
# next we need to grab an authenticator
from .auth import Authenticator

# this class will be use by our different apis to actual handle the requests
# we will have two apis, one for a user to interface with a local database
# and another for a user to interact with a server, either way the server or the user api
# will interface with this alone
class BaseApi:
    # first we need to initialize all our other objects
    def __init__(self, path):
        self.authenticator = Authenticator(path) # then we create the authenticator object with the database connection
        self.token = None
    
    def login(self, username, password):
        self.token = self.authenticator.login(username, password, machineid.hashed_id())
        if self.token in (Authenticator.BAD_PASS, Authenticator.BAD_USER):
            return self.token
        return Authenticator.SUCCESS
    def logout(self):
        pass
    
    def signup(self):
        pass
    
    def check(self):
        return self.authenticator.get_key(*self.token, machineid.hashed_id())
    