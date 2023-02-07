import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.main import logger
import json

with open('C:/Users/3008362/AppData/Local/Programs/Python/Python311/Lib/MaxMods/tests/times.json', 'r') as file:

    data = json.load(file)

sorted_data = sorted(data, key=lambda x: x[1])

print(sorted_data)

for data in sorted_data:
    print(data)

# logger.setup_logger(client_logger_location = os.getcwd(), server_logger_location=None)

# from sqlalchemy import create_engine, Column, String, Table, MetaData

# from sqlalchemy.pool import StaticPool

# engine = create_engine('sqlite:///users.db', connect_args={'check_same_thread':False},
#                        poolclass=StaticPool)
# metadata = MetaData()
# users = Table('users', metadata,
#     Column('username', String, unique=True, primary_key=True),
#     Column('password', String),
#     Column('data', String)
# )
# metadata.create_all(engine)
# conn = engine.connect()

# @logger()
# def add_user():
#     # Add a user to the database
#     conn.execute(users.insert().values(username='user6', password='password1', data='some data'))

# @logger()
# def querry():
#     conn = engine.connect()
#     result = conn.execute(users.select().where(users.c.username == 'user8'))
#     user = result.fetchone()
#     print(user)
# add_user()
# querry()
# print(logger.times)