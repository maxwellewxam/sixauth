# Made with love by Max

VER = '1.1.0_DEV.1'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here
import machineid
from sqlalchemy import Column, String, LargeBinary
from cryptography.fernet import Fernet
# first we need a database connection
# next we need to grab an authenticator
from .auth import Authenticator
from .database import Database
from .constants import *

# this class will be use by our different apis to actual handle the requests
# we will have two apis, one for a user to interface with a local database
# and another for a user to interact with a server
class LocalUser:
    # first we need to initialize all our other objects
    def __init__(self, path: str):
        self.id = machineid.hashed_id() # get a unique id for the machine the user is using
        self.db = Database(path) # make the database connection
        self.authenticator = Authenticator(self.db) # then we create the authenticator object with the database connection
        self.user = None # predefine the user value to None
    
    # just make the new_user function available to the user
    def new_user(self, username: str, password: str):
        return self.authenticator.new_user(username, password)
    
    # next we need to let user login
    def login(self, username: str, password: str):
        self.user = self.authenticator.login(username, password, self.id) # use the authenticator to login
        if self.user in (BAD_PASS, BAD_USER): # check if the login failed
            return self.user # if it did, then return the failed result
        table = [ # this will hold our users data
            Column('key', String, primary_key=True, nullable=False),
            Column('value', LargeBinary, nullable=False)]
        self.table = self.db.table(self.user[0], table) # create the table for the user 
        return SUCCESS # return success
    
    # just make the update_username function available to the user properly
    def update_username(self, password: str, new_username: str):
        if type(self.user) != tuple:
            return BAD_USER
        return self.authenticator.update_username(self.user[0], password, new_username)
    
    # just make the update_password function available to the user properly
    def update_password(self, password: str, new_password: str):
        if type(self.user) != tuple:
            return BAD_USER
        return self.authenticator.update_password(self.user[0], password, new_password)
    
    # make the remove_user function available to the user and some other processing 
    def remove_user(self, password: str):
        if type(self.user) != tuple:
            return BAD_USER
        result = self.authenticator.remove_user(self.user[0], password)
        if result != SUCCESS:
            return result
        self.db.metadata.tables[self.table].drop(self.db.engine())
        return SUCCESS
        
    def find(self, key: str):
        if type(self.user) != tuple:
            return BAD_USER
        from_db = self.db.find(self.table, 'key', key)
        if not from_db:
            return NOT_FOUND
        auth_key = self.authenticator.get_key(*self.user, self.id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        return Fernet(auth_key).decrypt(from_db[1])
    
    def insert(self, key: str, value: bytes):
        if type(self.user) != tuple:
            return BAD_USER
        if self.db.find(self.table, 'key', key):
            return EXISTS
        auth_key = self.authenticator.get_key(*self.user, self.id)
        if auth_key in (BAD_USER, BAD_HWID, BAD_TOKEN):
            return auth_key
        self.db.insert(self.table, key=key, value=Fernet(auth_key).encrypt(value))
        return SUCCESS
        
