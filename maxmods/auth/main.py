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

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

# this lil john here is just used to get a file path to a folder where the module is stored
# for logging purposes, it just makes more sense to me to have logs stored in the module folder
# instead of the cwd, but i also made it user defined
from . import logs

# these are all the exceptions that this module will raise
# i could use like built in ones but ion feel like it so...
class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class DataError(BaseException): ...

# alr alr so first real thing here is this cache dict
# so this john will hold all the active users data for way quicker access
# the database holds the users data with a really strong encryption thats tough to compute
# and so we to pull the johns data from the db and and decrypt it once
# then store it in the cache with a weaker but way faster encryption
# this also means that if the john doesnt properly exit, any change made to the data before its saved will be lost
# a sacrifice im willing to make, also with i could put emoji's in here lol
# i lowk dont like just creating this thing like this but ion know a better way with out classes and whatnot
cache = {}

# here we begin to set up the loggers
# i have four different loggers, one for console 
# and one for debugging, then the same thing for the client side
# i want to change the client console logger to be
# a more indepth server logger and then reduce the amount of things
# logged by the server, cause rn if you have like 100 clients connect to the server and 
# manipulate data, log files get into he gigabytes of size
# im actually gonna do that now which makes all of what i said irrelevant 
# but atleast you get to see my thought prosses
# ok but here we define the names, levels, and formats of the loggers
server_console = logging.getLogger('server_console')
server_logger = logging.getLogger('server_logger')
server_big_logger = logging.getLogger('server_big_logger')
client_logger = logging.getLogger('client_logger')
server_console.setLevel(logging.INFO)
server_logger.setLevel(logging.INFO)
server_big_logger.setLevel(logging.INFO)
client_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# here we define the function that sets up the loggers and their default states
# we set things like log file paths and how much to log, the only changable things
# we also log that we have started a newlog and what handlers go to what loggers
def log_paths(client_logger_location = os.path.dirname(logs.__file__), server_logger_location = os.getcwd(), inDepthLogs = False): 
    global server_logger_handler
    global client_logger_handler
    server_logger_handler = logging.FileHandler(server_logger_location+'/server.log')
    client_logger_handler = logging.FileHandler(client_logger_location+'/client.log')
    server_console.addHandler(server_logger_handler)
    server_console.addHandler(console_handler)
    server_logger.addHandler(server_logger_handler)
    if inDepthLogs:
        server_big_logger.addHandler(server_logger_handler)
    client_logger.addHandler(client_logger_handler)
    server_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
    client_logger.info('VVV---------BEGIN-NEW-LOG----------VVV')
    server_logger_handler.setFormatter(formatter)
    client_logger_handler.setFormatter(formatter)

# and here we just run the defult state so that we are always logging something
# we can run the function above at anytime during runtime to change this
# it will show in the logs that a new log has started
# and from then on all the loggers will have the new paths and states
log_paths()

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
def check_and_remove(threshold, stop_flag):
    while not stop_flag.is_set():
        for key in list(cache):
            if time.time() - cache[key]['time'] > threshold:
                del cache[key]
                server_logger.info('A user timed out')
                server_big_logger.info(f'Current cache: {cache}')
        time.sleep(1)

# the only known issue with the checker is that
# if someone happens to terminate their session inbetween the time 
# the the checker checks how long its been inactive for
# and when the chacker actually goes to delete the cache
# the thread with throw a key error and then the server wouldnt have a 
# cache checker and the cache could then be targeted and bloated
# so this thread will restart the checker should that happen
# also i know i could put a try and accept statement with a pass
# but this way the thread will log the exception to the servers console
# and then i (or anyone else) can tell why the thread had an issue
# cause i lowk dont know if there are other potential problems with the checker
# ok but this is just a loop that will brake if the same stop flag from the checker loop
# is set, and the loop defines the thread and runs it
# then when the thread joines back to the keep alive thread
# it will loop and start a new checker thread
# should also mention that this is run in its own thread much like the checker is
def keep_alive(cache_threshold, stop_flag):
    while not stop_flag.is_set():
        t = threading.Thread(target=check_and_remove, args=(cache_threshold, stop_flag))
        t.start()
        t.join()

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
def encrypt_data(data, password, username):
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
def decrypt_data(data, password, username):
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
def encrypt_data_fast(message, key):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

# the key is sent by the client and the server doesnt have to do any work to make it
# this is way less secure and doesnt last any longer than one run of the client
# as the key is never stored on the client outside of the client script
# but because the data is not stored in a file this way it shouldnt need to be too secure i think
def decrypt_data_fast(message, key):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

# here are the password hashing functions
# these used to be baked into all the functions and hard to get to
# after doing more research about security with these kind of apps
# i realized i should move these outside of the functions to one place
# as these are ever changing as hardware and software change
# will be easier to update these when better hashing algorithms come out
def create_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

# as for now, bcrypt is the best password hashing lib
# and one of the easiest ones to use
# just hash the john then check if the password and the hash match
# obviously more than that happens, but this isnt a course on cryptograghy lol
def verify_password_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

# ok this function converts a numbers to their letter form
# we have this in a function because we use it alot and its really long
# and we use it because the jsonpath_ng module doesnt allow numbers in the 
# parser configuration, just do this regular conversion and the end user never knows we did it
# unless they look at the raw dict lol
def convert_numbers_to_words(text):
        return text.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')

# this lil john just checks if an object 
# is json serialized
# we do this because we make this check alot and i dont like
# try and except statements in like main code ya know
# rather have it in a dedicated function
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
def is_valid_key(data, id):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        server_big_logger.info(f'Key invalid, {id}')
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
def establish_connection(address):
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

# the first of the cache functions
# the chache has become one of the central points of this file lol
# all this does is creat a cache pointer for the user based on the id provided
# with the id being the key used to decrypt and encrypt things in the cache
# we also log what is in the cache if we are logging big things
def add_user(id):
    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
    cache[hash] = {'main':encrypt_data_fast([None,(None,None)],id), 'time':time.time()}
    server_big_logger.info(f'Current cache: {cache}')
    return hash

# this john here returns the data in the cache for a user
# we first chack to make sure that we have the right hash id pair
# then decrypt the data in the cache with the id and return
# a really easy and fast function
def find_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['time'] = time.time()
        server_big_logger.info(f'Current cache: {cache}')
        return decrypt_data_fast(cache[hash]['main'],id)
    return [False,(False,False)]

# this fuction is pretty cool too
# we do the same check, then we encrypt the data given and replace 
# the data in the cache with it
# all the cache functions are really easy
# and thats why its so fast
def update_user(hash, id, dbdat):
    if is_valid_key(cache[hash]['main'], id):
        cache[hash]['main'] = encrypt_data_fast(dbdat,id)
        cache[hash]['time'] = time.time()
        server_big_logger.info(f'Current cache: {cache}')
        return [None]
    return [False,(False,False)]

# and this last john just removes the users cache
# if we pass that key check again
# oh yeah also we log the changes in the cache
def delete_user(hash, id):
    if is_valid_key(cache[hash]['main'], id):
        del cache[hash]
        server_big_logger.info(f'Current cache: {cache}')
        return [None]
    return [False,(False,False)]

# this is the first of the many main opperations the user can preform
# this function will create a users account if it passes a bunch of checks
# basically all these functions are based on a code ssytem
# we send data and then we return a code and any other information needed
# so first we check that the username is a valid username
# then we check that the user doesnt exsist in the database already
# if all checks pass, the we create the users account and return a success code
def sign_up(app, db, User, **data):
    if data['username'] == '':
        return {'code':406}
    if data['username'].isalnum() == False:
        return {'code':406}
    with app.app_context():
        user_from_database = User.query.filter_by(username=data['username']).first()
    if user_from_database:
        return {'code':409}
    with app.app_context():
        db.session.add(User(username=data['username'], password=create_password_hash(data['password']), data=encrypt_data({}, data['username'], data['password'])))
        db.session.commit()
    return {'code':200}

def save_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if not is_json_serialized(data['data']):
        return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
    
    data_from_request = json.loads(data['data'])
    
    if data['location'] == '':
        update_user(data['hash'], data['id'], [data_from_request, userinfo_from_cache])
        return {'code':200, 'data':data_from_request}
    
    jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).update_or_create(user_from_cache, data_from_request)
    update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])
    return {'code':200, 'data':user_from_cache}

def delete_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    userinfo_from_cache = find_user(data['hash'], data['id'])[1]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        update_user(data['hash'], data['id'], [{}, userinfo_from_cache])
        return {'code':200}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:
        return {'code':416}
    
    del [match.context for match in parsed_location][0].value[str([match.path for match in parsed_location][0])]
    update_user(data['hash'], data['id'], [user_from_cache, userinfo_from_cache])
    return {'code':200}

def log_out(app, db, passfields, User, **data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    username, password = find_user(data['hash'], data['id'])[1]

    if user_from_cache == None or user_from_cache == False:
        return {'code':200}
    
    with app.app_context():
        user_from_database = User.query.filter_by(username=username).first()
    
    if not user_from_database:
        return {'code':420, 'data':user_from_cache, 'error':'could not find user to logout'}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code': 423}

    with app.app_context():
        db.session.delete(user_from_database)
        db.session.add(User(username=username, password=create_password_hash(password), data=encrypt_data(user_from_cache, username, password)))
        db.session.commit()
    
    update_user(data['hash'], data['id'], [None,(None,None)])
    return {'code':200}

def remove_account(app, db, passfields, User, **data):
    username, password = find_user(data['hash'], data['id'])[1]
    #client_logger.info(f'Username from cache: {username}') 
    with app.app_context():
        user_from_database = User.query.filter_by(username=username).first()
        #client_logger.info(f'Username from database: {user_from_database}')
    if not user_from_database or username == False:
        return {'code':423}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, password):
        return {'code':423}
    
    with app.app_context():
        db.session.delete(user_from_database)
        db.session.commit()
        
    update_user(data['hash'], data['id'], [None,(None,None)])
    return {'code':200}

def log_in(app, datfields, passfields, User, **data):
    if data['username'] == '':
        return {'code':406}
    
    if data['username'].isalnum() == False:
        return {'code':406}
    
    with app.app_context():
        user_from_database = User.query.filter_by(username=data['username']).first()

    if not user_from_database:
        return {'code':404}
    
    datPass = marshal(user_from_database, passfields)['password']
    
    if not verify_password_hash(datPass, data['password']):
        return {'code':401}
        
    if update_user(data['hash'], data['id'], [decrypt_data(marshal(user_from_database, datfields)['data'], data['username'], data['password']), (data['username'], data['password'])])[0] == False:
        return {'code':423}
    return {'code':200}

def load_data(**data):
    user_from_cache = find_user(data['hash'], data['id'])[0]
    
    if user_from_cache == None or user_from_cache == False:
        return {'code':423}
    
    if data['location'] == '':
        return {'code':202, 'data':user_from_cache}
    
    parsed_location = jsonpath_ng.parse(convert_numbers_to_words(data['location'].replace('/', '.').replace(' ', '-'))).find(user_from_cache)
    
    if parsed_location == []:

            return {'code':416}

    return {'code':202, 'data':[match.value for match in parsed_location][0]}

def create_session(**data):
    user_hash = add_user(data['id'])

    return {'code':101, 'hash':user_hash}

def end_session(**data):
    if delete_user(data['hash'], data['id'])[0] == False:

        return {'code':423}

    return {'code':200}

def backend_session(address):
    f, client_socket = establish_connection(address)
    client_logger.info(f'Connected to: {address}')
    def send(**data):
        client_socket.send(f.encrypt(json.dumps(data).encode('utf-8')))
        return json.loads(f.decrypt(client_socket.recv(1024)).decode())
    return send

def frontend_session(path = os.getcwd()):
    
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
    client_logger.info(f'Database located at: sqlite:///{path}/database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db = SQLAlchemy(app)            

    class User(db.Model):
        username = db.Column(db.String, nullable=False, primary_key = True)
        password = db.Column(db.String, nullable=False)
        data = db.Column(db.String)

        def __init__(self, username, password, data):
            self.username = username
            self.password = password
            self.data = data

    with app.app_context():
        db.create_all()
        
    datfields = {'data': fields.Raw}
    passfields = {'password': fields.String}
    
    def action(**data):
        if data['func'] == 'create_session':
            return create_session(**data)
        
        elif data['func'] == 'sign_up':
            return sign_up(app, db, User, **data)
        
        elif data['func'] == 'save_data':
            return save_data(**data)

        elif data['func'] == 'delete_data':
            return delete_data(**data)
            
        elif data['func'] == 'log_out':
            return log_out(app, db, passfields, User, **data)
            
        elif data['func'] == 'remove_account':
            return remove_account(app, db, passfields, User, **data)
    
        elif data['func'] == 'log_in':
            return log_in(app, datfields, passfields, User, **data)
            
        elif data['func'] == 'load_data':
            return load_data(**data)
        
        elif data['func'] == 'end_session':
            return end_session(**data)
    
    return action

def server(host, port, cache_threshold = 300, debug = False, log_senseitive_info = False):
    
    if debug:
        server_logger.addHandler(console_handler)
        client_logger.addHandler(console_handler)
        server_console.info('Debug mode active')
        
    if log_senseitive_info:
        server_console.info('WARNING: SENSEITIVE INFORMATION BEING LOGGED')
        
    client_logger.addHandler(server_logger_handler)
    
    # Run the server
    # Create a frontend session for the server
    session = frontend_session()
    stop_flag1 = threading.Event()
    
    t = threading.Thread(target=keep_alive, args=(cache_threshold, stop_flag1))
    t.start()
    
    #Generate an ECDH key pair for the server
    server_private_key = ec.generate_private_key(ec.SECP384R1, default_backend())
    server_public_key = server_private_key.public_key()

    #Serialize the server's public key
    server_public_key_bytes = server_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)

    clients = []
    
    def exit():
        stop_flag1.set()
        t.join()
        server_logger.info('Cache thread exited')
        for client_s, client_t in clients:
            client_s.close()
            client_t.join()
        server_logger.info('All client threads exited')
            
    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    #HMM
    server_socket.setblocking(0)
    
    # Bind the socket to the port
    server_socket.bind((host, port))

    # Listen for incoming connections
    server_socket.listen()
    server_console.info('Server started')
    server_console.info('Press Ctrl+C to exit')
    server_console.info(f"Listening for incoming connections on {host}:{port}")

    def handle_client(client_socket, f, client_address, session, stop_flag):
    # Pass requests from the client to the servers database session
        try:
            while not stop_flag.is_set():

                try:
                    recv = client_socket.recv(1024)
                    server_logger.info(f"Received data from client: {client_address}: {recv}")
                    
                    if recv != b'':
                        try:
                            data = json.loads(f.decrypt(recv).decode())
                            
                            if log_senseitive_info:
                                server_logger.info(f"Received: {data}")
                            elif data['func'] != 'sign_up' and data['func'] != 'create_session':
                                server_logger.info(f"Received: {data['func']}, {data['hash']}")
                            
                            response = session(**data)
                            
                            server_logger.info(f'Response: {response["code"]}')
                            
                            client_socket.send(f.encrypt(json.dumps(response).encode('utf-8')))
                            
                            if data['func'] == 'end_session' and response['code'] == 200:
                                break
                        
                        except BaseException as err:
                            if type(err) == KeyError:
                                client_socket.send(f.encrypt(json.dumps({'code':420, 'data':None, 'error':f'Couldnt find user in cache, contact owner to recover any data, \nuse this key: {str(err)}\nuse this id: \'{str(data["id"])}\''}).encode('utf-8')))
                            else:
                                client_socket.send(f.encrypt(json.dumps({'code':420, 'data':None, 'error':str(err)}).encode('utf-8')))
                            
                            tb = traceback.extract_tb(sys.exc_info()[2])
                            line_number = tb[-1][1]
                            server_logger.info(f'Request prossesing for {client_address} failed, Error on line {line_number}: {str(type(err))}:{str(err)}\n{str(tb)}')
                            break
                    else:
                        break
                    
                except BlockingIOError:
                    pass
                
        except BaseException as err:
            server_console.info(f'Client thread did not exit successfully, Error: {err}')
        # End the connection when loop breaks
        server_logger.info(f"Closed connection from {client_address}")
        client_socket.close()
        for sock, thread in clients:
            if sock == client_socket:
                clients.remove((client_socket, thread))
    #Accept an incoming connection
    try:
        while not stop_flag1.is_set():
            try:
                client_socket, client_address = server_socket.accept()

                #Wait for the client's public key
                client_public_key_bytes = client_socket.recv(1024)
                
                #Deserialize the client's public key
                client_public_key = serialization.load_pem_public_key(
                client_public_key_bytes, default_backend())

                #Send the server's public key to the client
                client_socket.send(server_public_key_bytes)

                #Calculate the shared secret key using ECDH
                shared_secret = server_private_key.exchange(ec.ECDH(), client_public_key)

                #Use HKDF to derive a symmetric key from the shared secret
                kdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b"session key",
                backend=default_backend()
                )
                key = kdf.derive(shared_secret)

                #Use the symmetric key to encrypt and decrypt messages
                f = Fernet(base64.urlsafe_b64encode(key))
                server_logger.info(f"Received incoming connection from {client_address}")
                
                #Create a new thread to handle the incoming connection
                client_thread = threading.Thread(target=handle_client, args=(client_socket, f, client_address, session, stop_flag1))
                client_thread.start()
                server_logger.info('Client thread started')
                clients.append((client_socket, client_thread))
            except BlockingIOError:
                pass
    except KeyboardInterrupt:
        exit()
        server_console.info('Exited')
    except BaseException as err:
        exit()
        server_console.info(f'Program did not exit successfully, Error: {err}')
