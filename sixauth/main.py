# Made with love by Max

VER = '1.1.0_DEV.1'

# this file will be the main backbone of our application
# here we will do all out maintenance stuff
# all other files get invoked from here

# first we need a database connection
from .database import Database
# next we need to grab an authenticator
from .auth import Authenticator

# this class will be use by our different apis to actual handle the requests
# we will have two apis, one for a user to interface with a local database
# and another for a user to interact with a server, either way the server or the user api
# will interface with this alone
class BaseApi:
    # first we need to initialize all our other objects
    def __init__(self, path):
        self.db = Database() # we create/connect to our database file at "db_path = f'sqlite:///{path}/database.db'" to whom that will be useful, here it is, idk if you could possibly specify a remote server in the path variable or if the connection only works for sqlite databases
        self.authenticator = Authenticator(path) # then we create the authenticator object with the database connection
    
    