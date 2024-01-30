# Made with love by Max

# this file will handle all authentication related stuff
# all we need is a database connection and
# ways to authenticate, create, delete, and update users

import bcrypt
import uuid
import secrets
import base64
import pytz
import hashlib
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, Column, String, Table, MetaData, LargeBinary, Uuid
from sqlalchemy.pool import StaticPool
from datetime import datetime, timedelta   
        
class Database:
    # first we connect to the database
    def __init__(self, path:str):
        db_path = f'sqlite:///{path}' # define the path to the database
        self.engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool) # create a database engine
        self.metadata = MetaData() # metadata for the database too?
        self.connection = self.engine.connect() # connect to the database
    # we need this to save everything to the database when we are done
    def close(self):
        self.connection.commit()
        self.connection.close()
    
    def make_table(self, name, columns:list[Column]):
        table = Table(name, self.metadata)
        for column in columns:
                table.append_column(column)
        self.metadata.create_all(self.engine)
        return table
    
    # we need to grab things from the database
    def find(self, table:Table, column:Column, value):
        return self.connection.execute(table.select().where(getattr(table.c, column) == value)).fetchone()
    
    def insert(self, table:Table, **values):
        return self.connection.execute(table.insert().values(**values))
    
    def update(self, table:Table, column, key, **values):
        return self.connection.execute(table.update().where(getattr(table.c, column) == key).values(**values))
    
db = Database(f'{os.getcwd()}/test.db')    
users_table = [
    Column('user_id', Uuid, primary_key=True, nullable=False),
    Column('username', String, unique=True, nullable=False),
    Column('password', LargeBinary, nullable=False),
    Column('salt', LargeBinary, nullable=False)
]
table = db.make_table('Users', users_table)
db.insert(users_table, user_id=uuid.uuid4(), username='max', password='password'.encode(), salt='salt'.encode())
db.close()

    