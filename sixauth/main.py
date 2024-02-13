# Made with love by Max
import machineid

VER = '1.1.0_DEV.1'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here

from sqlalchemy import Column, String, LargeBinary
from cryptography.fernet import Fernet
# first we need a database connection
# next we need to grab an authenticator
from .auth import Authenticator
from .database import Database

# this class will be use by our different apis to actual handle the requests
# we will have two apis, one for a user to interface with a local database
# and another for a user to interact with a server
class LocalUser:
    # first we need to initialize all our other objects
    def __init__(self, path):
        self.id = machineid.hashed_id() # get a unique id for the machine the user is using
        self.db = Database(path) # make the database connection
        self.authenticator = Authenticator(self.db) # then we create the authenticator object with the database connection
        self.user = None
    
    def new_user(self, username, password):
        return self.authenticator.new_user(username, password)
    
    def login(self, username, password):
        self.user = self.authenticator.login(username, password, self.id)
        if self.user in (Authenticator.BAD_PASS, Authenticator.BAD_USER):
            return self.user
        table = [ # this will hold our users data
            Column('key', String, primary_key=True, nullable=False),
            Column('value', LargeBinary, nullable=False)]
        self.table = self.db.table(self.user[0], table)
        return Authenticator.SUCCESS
    
    def update_username(self, password: str, new_username: str):
        if type(self.user) != tuple:
            return Authenticator.BAD_USER
        return self.authenticator.update_username(self.user[0], password, new_username)
    
    def update_password(self, password, new_password):
        if type(self.user) != tuple:
            return Authenticator.BAD_USER
        return self.authenticator.update_password(self.user[0], password, new_password)
    
    def remove_user(self, password: str):
        if type(self.user) != tuple:
            return Authenticator.BAD_USER
        return self.authenticator.remove_user(self.user[0], password)
    
    def find(self, key):
        if type(self.user) != tuple:
            return Authenticator.BAD_USER
        from_db = self.db.find(self.table, 'key', key)
        if not from_db:
            return Database.NOT_FOUND
        auth_key = self.authenticator.get_key(*self.user, self.id)
        if auth_key in (Authenticator.BAD_USER, Authenticator.BAD_HWID, Authenticator.BAD_TOKEN):
            return auth_key
        return Fernet(auth_key).decrypt(from_db[1])
        
