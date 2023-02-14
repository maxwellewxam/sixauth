# ignore this first chunk of comments if you dont wanna hear me rant ;)
# so you wanna know whats going on in this file eh
# basically these are all functions the auth module uses to manage ya things
# because this is my file and im not regulated by sum community
# im gonna make the comments for this my way bozo
# you should still beable to understand it but youll def have fun reading it lmao
# ion finna be rude or out rageous or nun, you can lowk read this to your grandma no problem
# also if anyone sees this, please lemme know of any improvements i can make to the code, not the comments lol
# however if something doesnt make sense or i made a grammatical error, please tell me!
# also also i made this whole file without classes because i felt like it
# object oriented programming is cool and all, and by the gods i love classes
# but i challenged myself to make this without them and i also remember sum vid i watch about
# O.O.P. being bad so i decided to not use it
# only ecxeption to this rule is that the code used for the database connection uses a class
# i lowk dont know a different way without rewriting the whole database connection with a different module or sum
# also if you want to know useage for these raw functions instead of using the auth file
# i will have the useage to the 'server', 'frontend_session', and 'backend_session' functions in the comments on them
# and for all the other functions
# well if you want to use those you should beable to understand how to use them from their comments too
# and if you dont then you probably shouldnt use them

# ok so these are all the imports i use
# my fav lowk being josnpath_ng or cryptography
# the two modules that really pull their weight arround here
# like flask was lowk only used in earlier versions for the online server connections
# it came preloaded with a fye ass database api and so it became heavily ingraned into the base of alot of the functions
# but now i use sockets and cryptography, and i just havent felt the need to rewrite alot of the database code
# i mean it shouldnt be hard but im here now an nun else we gonna do
import hashlib
import jsonpath_ng
import os
import sys
import json
import base64
import bcrypt
import socket
import time
import threading
import logging
import traceback
import asyncio

from datetime import datetime
from sqlalchemy import create_engine, Column, String, Table, MetaData
from sqlalchemy.pool import StaticPool
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# this lil john here is just used to get a file path to the folder where the module is stored
# for logging purposes, it just makes more sense to me to have logs stored in the module folder
# instead of the cwd, but i also made it user defined if you so choose
from .logs.log_class import Logger


# these are all the exceptions that this module will raise
# i could use like built in ones but ion feel like it so...
class AuthError(Exception): ...
class LocationError(AuthError): ...
class AuthenticationError(AuthError): ...
class UsernameError(AuthError): ...
class PasswordError(AuthError): ...
class DataError(AuthError): ...

old_hook = sys.excepthook

def exception_hook(exc_type, value, tb):
    tb = traceback.format_exception(exc_type, value=value, tb=tb)
    if exc_type.__bases__[0] == AuthError:
        bottom = tb[-1:]
        tb = tb[:-3]
        tb.append(bottom[0].strip('sixauth.main.'))
        tb = ''.join(tb)
        print(tb)
    else:
        old_hook(exc_type, value, tb)
    
sys.excepthook = exception_hook

# alr alr so first real thing here is this cache dict
# so this john will hold all the active users data for way quicker access
# the database holds the users data with a really strong encryption thats tough to compute
# and so we to pull the johns data from the db and and decrypt it once
# then store it in the cache with a weaker but way faster encryption
# this also means that if the john doesnt properly exit, any change made to the data before its saved will be lost
# a sacrifice im willing to make, also with i could put emoji's in here lol
# i lowk dont like just creating this thing like this but ion know a better way with out classes and whatnot
cache = {}

# here we are setting up the loggers to be passed to the logging module
# get level and name and format, all the fun stuff
server_console = logging.getLogger('server_console')
client_console = logging.getLogger('client_console')
server_logger = logging.getLogger('server_logger')
client_logger = logging.getLogger('client_logger')
server_console.setLevel(logging.INFO)
client_console.setLevel(logging.INFO)
server_logger.setLevel(logging.INFO)
client_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# and here we just run the defult state so that we are always logging something
# it will show in the logs that a new log has started
# and from then on all the loggers will have the new paths and states
# you can from main import logger and then run the setup_logger method to change how the logger logs things
logger = Logger(server_console, client_console, server_logger, client_logger, console_handler, formatter).setup_logger(server_logger_location=None)

# now for the first big function here
# this is the cache check loop that we run in a separate thread
# we setup and run this only when starting a server but if you wanted
# you could run this on a thread of your own for the client or the server
# but what this john does is pretty important for a server
# when a user establishes a connection to a server, a cache is made
# this makes things faster, however the cache is only removed when the connection is properly exitied
# if an error occurs and the cach is never removed there is no way for it to be removed
# except for this function, everytime a user does anything involving the cache
# we update the current time of that users cache, and then this function constanly 
# checks how long its been since the time was set
# if the time is past a defined threshold, then we delete it and declare in the log that a user timed out
# so save resources we only run this chack once a second
# also the stop flag stops this thread from the main thread
@logger(is_log_more=True)
def cache_timeout_thread(threshold, stop_flag):
    while not stop_flag.is_set():
        try:
            for key in list(cache):
                if time.time() - cache[key]['time'] > threshold:
                    del cache[key]
            time.sleep(1)
        except Exception as err:
            server_console.log(err)

# and here is one of the first functions ever made in this file
# the is the encrypt function, the hard to compute one
# this function should be called with the username and password and keys and salt
# this will return the data but encrypted to be stored in the database for long term
# not much to say other then that age and what not
# when this function was made it was very much a black box to me
# just put inputs get outputs
# however i now know more about how encrypting works with the cyrptography module
# so first we take the data, a dict, and convert it to bytes with the json module
# then we define a key driver object and derive the key from the password
# then create a fernet object with with the key and then encrypt the data 
# with the fernet object, and then return it, easy!
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data(data, username, password):
    json_data = json.dumps(data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(json_data.encode()).decode()

# alr now this function is like part two of the encrypt function
# all the same info about it, first function like ever and yada yada
# only difference is that this function decrypts the data instead
# we make a key deriving object then derive the key from the password
# then make a fernet object with that key and decrypt the data and then turn it back into a dict
# return that dict and easy money
# for the both of these functions tho, i dont know if they are the best way to do this
# its the way we have and untill told otherwise im not changing it lol
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data(data, username, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(data.encode()).decode())

# now here we have a much faster encrypt and decrypt function pair
# just have the message and the key
# very quickly do everything that the above functions do 
# except for derive the key
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data_fast(message, key):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

# the key is sent by the client and the server doesnt have to do any work to make it
# this is way less secure and doesnt last any longer than one run of the client
# as the key is never stored on the client outside of the client script
# but because the data is not stored in a file this way it shouldnt need to be too secure i think
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data_fast(message, key):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

# here are the password hashing functions
# these used to be baked into all the functions and hard to get to
# after doing more research about security with these kind of apps
# i realized i should move these outside of the functions to one place
# as these are ever changing as hardware and software change
# will be easier to update these when better hashing algorithms come out
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

# as for now, bcrypt is the best password hashing lib
# and one of the easiest ones to use
# just hash the john then check if the password and the hash match
# obviously more than that happens, but this isnt a course on cryptograghy lol
@logger(is_log_more=True, in_sensitive=True)
def verify_password_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

# ok this function converts a numbers to their letter form
# we have this in a function because we use it alot and its really long
# and we use it because the jsonpath_ng module doesnt allow numbers in the 
# parser configuration, just do this regular conversion and the end user never knows we did it
# unless they look at the raw dict lol
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def convert_numbers_to_words(data):
        return data.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')

# this lil john just checks if an object 
# is json serialized
# we do this because we make this check alot and i dont like
# try and except statements in like main code ya know
# rather have it in a dedicated function
@logger(is_log_more=True, in_sensitive=True)
def is_json_serialized(obj):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

# this function is used for the cache
# just like i said above, i dont like try and except statements in like main code
# just moved it to its own function
# we use this in the cache functions to check if the key provided by the client works for 
# the hash they are trying to access, if not, boot them
@logger(is_log_more=True, in_sensitive=True)
def is_valid_key(data, id):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        return False

# now this is a big one lol
# so this is the function the client uses to establish a connection to the server
# this will return a fernet object that can be used to encrypt and decrypt messages for the server
# so the first thing we do is create a public and private key pair
# then make the socket, and send the server the clients public key
# then the server sends back its public key
# then we create the shared key based on the client private key and the servers public key
# then we make another key deriving object and derive the key from the shared key
# then make the fernet object with that derived key and now we can send encrypted messages
# we also return the socket connection with the server so you can send and recive messages
# actually not that big ngl, just alot of data moving to securly get a shared key
# this code was half created by the chatGPT bot, was using ssl before this and was having trouble with certs
@logger(is_log_more=True)
def establish_client_connection(address):
    client_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    client_public_key = client_private_key.public_key()
    client_public_key_bytes = client_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    client_socket = socket.socket()
    connection_info = address.split(':')
    client_socket.connect((connection_info[0], int(connection_info[1])))
    client_socket.send(client_public_key_bytes)
    server_public_key_bytes = client_socket.recv(1024)
    server_public_key = serialization.load_pem_public_key(
    server_public_key_bytes, default_backend())
    shared_secret = client_private_key.exchange(ec.ECDH(), server_public_key)
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend())
    key = kdf.derive(shared_secret)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f, client_socket


def make_location(dict, path, data):
    path = path.split('/')
    for pos, name in enumerate(path):
        if not len([match for match in dict.keys() if match == name]) > 0:
            dict[name] = {'data': None, 'folder':{}}
        if len(path)==pos+1:
            dict[name]['data'] = data
            return
        dict = dict[name]['folder']
       
        
def find_data(dict, path):
    path = path.split('/')
    for pos, name in enumerate(path):
        if len(path)==pos+1:
            return dict[name]
        dict = dict[name]['folder']
    
        
def delete_location(dict, path):
    path = path.split('/')
    for pos, name in enumerate(path):
        if len(path)==pos+1:
            del dict[name]
            return {'code':200}
        dict = dict[name]['folder']

# the first of the cache functions
# the chache has become one of the central points of this file lol
# all this does is creat a cache pointer for the user based on the id provided
# with the id being the key used to decrypt and encrypt things in the cache
# we also log what is in the cache if we are logging big things
# oh and this returns the a dict with a succsess code and pointer, i call it hash just because its the hash of the id plus datetime as a way of ensuring 
# no two hashes are the same
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def add_user(id):
    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
    cache[hash] = {'main':encrypt_data_fast([None,(None,None)],id), 'time':time.time()}
    return {'code':200, 'hash':hash}

# this john here returns the data in the cache for a user
# we first chack to make sure that we have the right hash id pair
# then decrypt the data in the cache with the id and return
# a really easy and fast function
# also in this function we do a check to see if the user
# has info in the cache or if they just have a empty cache instance
# this is used for certain validations in functions
# so like if the user creates a cache but then tries to save data 
# that code with throw, otherwise if the user updates the cache with their database info
# then that code will no longer throw, also when the user logs out, the info in the cache
# is set the same way as when their first added, so [None,(None,None)]
# the default state of the cache
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def find_user(hash, id):
    if not is_valid_key(cache[hash]['main'], id):
        return {'code':500}
    cache[hash]['time'] = time.time()
    data = decrypt_data_fast(cache[hash]['main'],id)
    if data[0] == None:
        return {'code':500}
    return {'code':200, 'data':data}

# this fuction is pretty cool too
# we do the same check, then we encrypt the data given and replace 
# the data in the cache with it
# all the cache functions are really easy
# and thats why its so fast
@logger(is_log_more=True, in_sensitive=True)
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['main'] = encrypt_data_fast(dbdat,id)
        cache[hash]['time'] = time.time()
        return {'code':200}
    return {'code':500}

# and this last john just removes the users cache
# if we pass that key check again
# oh yeah also we log the changes in the cache
@logger(is_log_more=True, in_sensitive=True)
def delete_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        del cache[hash]
        return {'code':200}
    return {'code':500}

# this is the first of the many main opperations the user can preform
# this function will create a users account if it passes a bunch of checks
# basically all these functions are based on a code system
# we send data and then we return a code and any other information needed
# so first we check that the username is a valid username
# then we check that the user doesnt exsist in the database already
# if all checks pass, then we create the users account and return a success code
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def sign_up(conn, users, **data):
    if data['username'] == '':
        return {'code':406}
    if data['username'].isalnum() == False:
        return {'code':406}
    user_from_database = conn.execute(users.select().where(users.c.username == data['username'])).fetchone()
    if user_from_database:
        return {'code':409}
    conn.execute(users.insert().values(username=data['username'], password=create_password_hash(data['password']), data=encrypt_data({}, data['username'], data['password'])))
    return {'code':200}

# save data is pretty simple as well
# also first off, all these functions are in no particular order
# like the whole file is just functions created at some point before they are needed
# ok but back to this, so the first thing we do is grab all the users info in the cache
# then check to make sure that the cache function executed correctly
# then we check to see if the data sent is json serialized before trying to loads it
# then we do a check for when the location is '', if true we will then just replace all the users data with the data given
# if we dont do that then we will use jsonpath_ng to parse the dict of users data and then
# update or create the data into the location
# send this updated dict back to the cache and then return the function with 200
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def save_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if not is_json_serialized(data['data']):
        return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
    data_from_request = json.loads(data['data'])
    if data['location'] == '':
        #update_user(data['hash'], data['id'], [{'':data_from_request}, user_from_cache['data'][1]])
        return {'code':416}#, 'data':data_from_request}
    #jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).update_or_create(user_from_cache['data'][0], data_from_request)
    make_location(user_from_cache['data'][0], data['location'], data_from_request)
    update_user(data['hash'], data['id'], [user_from_cache['data'][0], user_from_cache['data'][1]])
    return {'code':200, 'data':user_from_cache['data'][0]}

# now for deleting data from the database
# we kinda so the same things
# fetch the user from the cache, check to makesure that was successful
# then we have a special case whene the location is '' where we just put an empty dict into the cache
# otherwise we use jsonpath_ng to run through the dict of users data and then delete what data it finds
# oh and if jsonpath_ng cant find the location then we return an error code for that
# then we put the updated dict back into the cache and return the success code
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def delete_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if data['location'] == '':
        update_user(data['hash'], data['id'], [{}, user_from_cache['data'][1]])
        return {'code':200}
    delete_location(user_from_cache['data'][0], data['location'])
    # parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache['data'][0])
    # if parsed_location == []:
    #     return {'code':416}
    # del [match.context for match in parsed_location][0].value[str([match.path for match in parsed_location][0])]
    update_user(data['hash'], data['id'], [user_from_cache['data'][0], user_from_cache['data'][1]])
    return {'code':200}

# ok this is the logout function, this function is very important as its the only way to save info to the database
# in the auth file we run logout before every login anf terminate call, this is to eensure that the previous user is saved
# ok so first thing we do is fetch the data from the cache, very typical for these functions
# make sure that the fetch didnt return an error code
# then we fetch the user from the database
# makesure that the user actually exists in the database, and if they dont we return the data in the cache for saftey
# then we chack that the password in the cache is the same as in the database
# then we update the database with the data in the cache
# we clear the data in the cache and return a succsess code
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def log_out(conn, users, **data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':200}
    user_from_database = conn.execute(users.select().where(users.c.username == data['username'])).fetchone()
    if not user_from_database:
        return {'code':420, 'data':user_from_cache['data'], 'error':'could not find user to logout'}
    if not verify_password_hash(user_from_database[1], password=user_from_cache['data'][1][1]):
        return {'code': 423}
    conn.execute(users.update().where(users.c.username == user_from_cache['data'][1][0]).values(data=encrypt_data(user_from_cache['data'][0], user_from_cache['data'][1][0], user_from_cache['data'][1][1])))
    update_user(data['hash'], data['id'], [None,(None,None)])
    return {'code':200}

# for removing an account its very simmilar 
# fetch cache and check status then fetch database and check status
# run cross checks on database data and cache data
# then remove the user from the database
# and return success code
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def remove_account(conn, users, **data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return{'code':423}
    user_from_database = conn.execute(users.select().where(users.c.username == user_from_cache['data'][1][0])).fetchone()
    if not user_from_database:
        return {'code':423}
    if not verify_password_hash(user_from_database[1], password=user_from_cache['data'][1][1]):
        return {'code':423}
    conn.execute(users.delete().where(users.c.username == user_from_cache['data'][1][0]))
    update_user(data['hash'], data['id'], [None,(None,None)])
    return {'code':200}

# here is the log out function!
# we use this to log in a user
# we just do some standard checks
# good username and password and that they match with the database
# then return a success code
# nothing crazy, but this is the only function that can load userdata from database to cache
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def log_in(conn, users, **data):
    if data['username'] == '':
        return {'code':406}
    if data['username'].isalnum() == False:
        return {'code':406}
    user_from_database = conn.execute(users.select().where(users.c.username == data['username'])).fetchone()
    if not user_from_database:
        return {'code':404}
    if not verify_password_hash(user_from_database[1], password=data['password']):
        return {'code':401}   
    cache_data = [decrypt_data(user_from_database[2], data['username'], data['password']), (data['username'], data['password'])]
    if update_user(data['hash'], data['id'], cache_data)['code'] == 500:
        return {'code':423}
    return {'code':200}

# load data :sunglasses:
# haha i love discord emoji annotation
# anyways this function is crazy
# kidding, just do more checks 
# then use jsonpath_ng to retrive the data
# the return 202 to tell the request handler that we also have data coming back to it
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def load_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])
    if user_from_cache['code'] == 500:
        return {'code':423}
    if data['location'] == '':
        return {'code':202, 'data':user_from_cache['data'][0]}
    #parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache['data'][0])
    #if parsed_location == []:
            #return {'code':416}
    val = find_data(user_from_cache['data'][0], data['location'])
    return {'code':202, 'data':val}#[match.value for match in parsed_location][0]}

# the crate session function
# this john just makes a position in the cache for the client
# then the any users on the client use that cache position for data storage
# we also return the cache pointer for the client to use
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_session(**data):
    user_hash = add_user(data['id'])['hash']
    return {'code':201, 'hash':user_hash}

# and the end session function does the opposite
# if finds the pointer and checks itd validity and then deletes it!
# easy money if i do say so myself
@logger(is_log_more=True, in_sensitive=True)
def end_session(**data):
    if delete_user(data['hash'], data['id'])['code'] == 500:
        return {'code':423}
    return {'code':200}

# oo the backend session john
# this mane is called and sets up a connection with the server
# then it returns a funtion that can send a recive data from the client
@logger()
def backend_session(address):
    f, client_socket = establish_client_connection(address)
    client_logger.info(f'Connected to: {address}')
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data):
        client_socket.send(f.encrypt(json.dumps(data).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(1024)).decode())
    return session

# im lowk getting lazy writing these and would love encouragement to do better lol
# enewaz this is the frontend session
# it starts up a database connection and then returns a function that wraps all the above functions
@logger()
def frontend_session(path = os.getcwd(), test_mode = False):
    db_path = f'sqlite:///{path}/database.db'
    client_logger.info(f'Database located at: {db_path}')
    engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool)
    metadata = MetaData()
    users = Table('users', metadata,
        Column('username', String, unique=True, primary_key=True),
        Column('password', String),
        Column('data', String))
    metadata.create_all(engine)
    conn = engine.connect()
    @logger(in_sensitive=True, out_sensitive=True)
    def session(**data):
        if data['code'] == 301:
            return create_session(**data)
        elif data['code'] == 302:
            return sign_up(conn, users, **data)
        elif data['code'] == 303:
            return save_data(**data)
        elif data['code'] == 304:
            return delete_data(**data)
        elif data['code'] == 305:
            return log_out(conn, users, **data)
        elif data['code'] == 306:
            return remove_account(conn, users, **data)
        elif data['code'] == 307:
            return log_in(conn, users, **data)
        elif data['code'] == 308:
            return load_data(**data)
        elif data['code'] == 309:
            return end_session(**data)
        elif data['code'] == 'test':
            if test_mode:
                return {'code':200, 'data':data}
    return session

# this is the start of the server functions
# the main client loop will receive all connections from the client after encryption is setup
# it will decrypt and parse the request and then give it to the servers frontend session
# then it will encrypt the result and send it back
@logger(is_log_more=True, is_server=True, in_sensitive=True)
async def main_client_loop(client_socket, client_address, f, loop, session, stop_flag1):
    while not stop_flag1.is_set():
        recv = await loop.sock_recv(client_socket, 1024)
        if recv == b'':
            break
        try:
            data = json.loads(f.decrypt(recv).decode())
            server_logger.info(f'{client_address} made request: {data["code"]}')
            response = session(**data)
            server_logger.info(f'response to {client_address}: {response["code"]}')
            await loop.sock_sendall(client_socket, f.encrypt(json.dumps(response).encode('utf-8')))
            if data['code'] == 309 and response['code'] == 200:
                break
        except BaseException as err:
            if type(err) == KeyError:
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':f'Couldnt find user in cache, contact owner to recover any data, \nuse this key: {str(err)}\nuse this id: \'{str(data["id"])}\''}).encode('utf-8')))
            else:
                await loop.sock_sendall(client_socket, f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
            tb = traceback.extract_tb(sys.exc_info()[2])
            line_number = tb[-1][1]
            server_logger.info(f'Request prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}')#\n{str(tb)}')

# the setup_client function will be called for every client that connects
# it will set up encryption and run the client main loop
@logger(is_server=True, in_sensitive=True)
async def setup_client(client_socket, client_address, server_public_key_bytes, stop_flag1, loop, session, server_private_key=None):
    client_public_key_bytes = await loop.sock_recv(client_socket, 1024)
    client_public_key = serialization.load_pem_public_key(
    client_public_key_bytes, default_backend())
    await loop.sock_sendall(client_socket, server_public_key_bytes)
    shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)
    kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"session key",
    backend=default_backend())
    key = kdf.derive(shared_secret)
    f = Fernet(base64.urlsafe_b64encode(key))
    await main_client_loop(client_socket, client_address, f, loop, session, stop_flag1)
    client_socket.close()

# the server main loop function will accept all new clients
# then create an async task for the client talk to
# then logs the task into a set too keep it alive and keep a running list of clients 
@logger(is_server=True, in_sensitive=True)
async def server_main_loop(server_socket, server_public_key_bytes, stop_flag1, session, server_private_key=None):
    loop = asyncio.get_event_loop()
    clients = set()
    while True:
        client_socket, client_address = await loop.sock_accept(server_socket)
        task = asyncio.create_task(setup_client(client_socket, client_address, server_public_key_bytes, stop_flag1, loop, session, server_private_key=server_private_key))
        clients.add(task)
        task.add_done_callback(clients.discard)

# and finally the server function is called by the end user to creat a server
# it will set up everything the server needs to run
# then run the main loop of the server
@logger(is_server=True)
def server(host, port, cache_threshold = 300, test_mode = False, use_default_logger = True):
    if use_default_logger:
        logger.setup_logger(client_logger_location=os.getcwd())
    session = frontend_session(test_mode=test_mode)
    stop_flag1 = threading.Event()
    t = threading.Thread(target=cache_timeout_thread, args=(cache_threshold, stop_flag1))
    t.start()
    server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()
    server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setblocking(0)
    server_socket.bind((host, port))
    server_socket.listen()
    server_console.info('Server started')
    server_console.info('Press Ctrl+C to exit')
    server_console.info(f"Listening for incoming connections on {host}:{port}")
    try:
        asyncio.run(server_main_loop(server_socket, server_public_key_bytes, stop_flag1, session, server_private_key=server_private_key))
    except KeyboardInterrupt:
        server_console.info('Server Closed')
    except BaseException as err:
        server_console.info(f'Server did not exit successfully, Error: {err}')
    finally:
        stop_flag1.set()
        t.join()