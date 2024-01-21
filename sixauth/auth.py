# this file will handle all authentication related stuff
# all we need is a database connection and
# ways to authenticate, create, delete, and update users
import bcrypt
import uuid
import secrets
import pytz
from sqlalchemy import create_engine, Column, String, Table, MetaData, LargeBinary, Uuid
from sqlalchemy.pool import StaticPool
from datetime import datetime, timedelta   
        
class Authenticator:
    # define class attributes
    BAD_PASS = 'BAD_PASS'
    BAD_USER = 'BAD_USER'
    BAD_TOKEN = 'BAD_TOKEN'
    SUCCESS = 'SUCCESS'
    # first we connect to the database
    def __init__(self, path):
        db_path = f'sqlite:///{path}/users.db' # define the path to the database
        engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool) # create a database engine
        metadata = MetaData() # metadata for the database too?
        self.users = Table('Users', metadata, # this will hold our users and their passwords
            Column('user_id', Uuid, primary_key=True, nullable=False),
            Column('username', String, unique=True, nullable=False),
            Column('password', LargeBinary, nullable=False),
            Column('salt', LargeBinary, nullable=False))
        metadata.create_all(engine) # create all the tables
        self.connection = engine.connect() # connect to the database
        self.store = {} # create a dict for tokens
        self.max_age = 3600 # set the max age in seconds

    # we need this to save everything to the database when we are done
    def close(self):
        self.connection.commit()
        self.connection.close()
    
    # we need users to authenticate!
    def new_user(self, username: str, password: str):
        if self.connection.execute(self.users.select().where(self.users.c.username == username)).fetchone(): # ok first we check if the user exists
            return self.BAD_USER # if they do, we return BAD_USER
        salt = bcrypt.gensalt() # create a salt
        hash = bcrypt.hashpw(password.encode('utf-8'), salt) # hash the password
        self.connection.execute(self.users.insert().values(user_id=uuid.uuid4(), username=username, password=hash, salt=salt)) # insert the new user in the database
        return self.SUCCESS # and we return SUCCESS
        
    # authenticate users that do exist
    def check_user_db(self, username: str, password: str):
        from_db = self.connection.execute(self.users.select().where(self.users.c.username == username)).fetchone() # first we grab the db entry for the user
        if not from_db: # then we check if the user exists
            return self.BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return self.BAD_PASS # if it isn't correct, we return BAD_PASS
        token = secrets.token_urlsafe() # then we generate a token if password is correct
        self.store[from_db[0]] = [token, datetime.now(pytz.utc) + timedelta(seconds=self.max_age)] # we add the token to the store
        return from_db[0], token # then lastly we return the token and uuid
    
    # faster check function for users with tokens
    def check_user_token(self, uuid:uuid.UUID, token: str):
        from_store = self.store.get(uuid) # grab the token from the store
        if not from_store: # check if the token exists
            return self.BAD_USER # if it doesn't, we return BAD_USER
        if token != from_store[0]: # next we check the token provided against the one in the store
            return self.BAD_TOKEN # if it isn't correct, we return BAD_TOKEN
        if from_store[1] <= datetime.now(pytz.utc): # check if token is expired
            return self.BAD_TOKEN # if it is, we return BAD_TOKEN
        return self.SUCCESS # if it isnt, we return SUCCESS
    
    # allow users to change their username
    def update_username(self, uuid:uuid.UUID, password: str, new_username: str):
        from_db = self.connection.execute(self.users.select().where(self.users.c.user_id == uuid)).fetchone() # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return self.BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return self.BAD_PASS # if the password is incorrect, we return BAD_PASS
        if self.connection.execute(self.users.select().where(self.users.c.username == new_username)).fetchone(): # check if the new username already exists
            return self.BAD_USER # if it does, we return BAD_USER
        self.connection.execute(self.users.update().where(self.users.c.user_id == uuid).values(username=new_username)) # update the username in the database
        return self.SUCCESS # and we return SUCCESS
    
    # allow users to change their password
    def update_password(self, uuid:uuid.UUID, password: str, new_password: str):
        from_db = self.connection.execute(self.users.select().where(self.users.c.user_id == uuid)).fetchone() # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return self.BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return self.BAD_PASS # if the password is incorrect, we return BAD_PASS
        self.connection.execute(self.users.update().where(self.users.c.user_id == uuid).values(password=bcrypt.hashpw(new_password.encode('utf-8'), from_db[3]))) # update the password in the database
        return self.SUCCESS # and we return SUCCESS
    
    # lastly, we can remove users from the database
    def remove_user(self, uuid:uuid.UUID, password:str):
        from_db = self.connection.execute(self.users.select().where(self.users.c.user_id == uuid)).fetchone() # first we grab the db entry for the uuid
        if not from_db: # then we check if the user exists
            return self.BAD_USER # if they dont, we return BAD_USER
        if from_db[2] != bcrypt.hashpw(password.encode('utf-8'), from_db[3]): # if they do, we check the password
            return self.BAD_PASS # if the password is incorrect, we return BAD_PASS
        self.connection.execute(self.users.delete().where(self.users.c.user_id == uuid)) # remove the user from the database
        return self.SUCCESS # and we return SUCCESS
    