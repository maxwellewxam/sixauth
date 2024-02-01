# Made with love by Max
import machineid

VER = '1.1.0_DEV.1'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here

# first we need a database connection
# next we need to grab an authenticator
from .auth import Authenticator
from .database import Database

# this class will be use by our different apis to actual handle the requests
# we will have two apis, one for a user to interface with a local database
# and another for a user to interact with a server, either way the server or the user api
# will interface with this alone
class LocalApi:
    # first we need to initialize all our other objects
    def __init__(self, path):
        self.db = Database(path) # make the database connection
        self.authenticator = Authenticator(self.db) # then we create the authenticator object with the database connection

class User:
    def __init__(self, api:LocalApi):
        self.id = machineid.hashed_id()
        self.api = api
        self.user = None
        
    def sign_up(self, username, password):
        return self.api.authenticator.new_user(username, password)
    
    def login(self, username, password):
        self.user = self.api.authenticator.login(username, password, self.id)
        if self.user in (Authenticator.BAD_PASS, Authenticator.BAD_USER):
            user = self.user
            self.user = None
            return user
        return Authenticator.SUCCESS
    
    def key(self):
        if self.user is None:
            return Authenticator.BAD_USER
        return self.api.authenticator.get_key(*self.user, self.id)