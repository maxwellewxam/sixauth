import hashlib
import jsonpath_ng
import os
import json
import base64
import bcrypt
import requests
import warnings

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken

class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class DataError(BaseException): ...

def encrypt(Data, password, username):
    Data1 = json.dumps(Data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(Data1.encode()).decode()

def decrypt(Data, password, username):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=100000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(Data.encode()).decode())

def encrypt_fast(message, key):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

def decrypt_fast(message, key):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

def create_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

def check_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

def num_to_str(text):
        return text.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')

def is_serialized(obj):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

def good_key(data, id):
    try:
        decrypt_fast(data, id)
        return True
    except InvalidToken:
        return False

class usercache:
    def __init__(self):
        self.users = {}
        
    def add(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        self.users[hash] = encrypt_fast([None,(None,None)],id)
        
        return hash
        
    def find(self, hash, id):
        if good_key(self.users[hash], id):
            return decrypt_fast(self.users[hash],id)
        
        return ['you being bad?',('you being bad?','you being bad?')]
        
    def update(self, hash, id, dbdat):
        if good_key(self.users[hash], id):
            self.users[hash] = encrypt_fast(dbdat,id)
            return [None]

        return ['you being bad?',('you being bad?','you being bad?')]

    def delete(self, hash, id):
        if good_key(self.users[hash], id):
            del self.users[hash]
            return [None]

        return ['you being bad?',('you being bad?','you being bad?')]

class jsonHandle:
    def __init__(self, Code):
        self.Code = Code
        
    def json(self):
        return self.Code
    
def HandleWrapper(func):
    def Wrapper(*args, **kwargs):
            return jsonHandle(func(*args, **kwargs))
    return Wrapper

def signup(context, **data):
    if data['Username'] == '':
        return {'Code':406}
    
    if data['Username'].isalnum() == False:
        return {'Code':406}
    
    with context.app.app_context():
        fromdat = context.DataMod.query.filter_by(Username=data['Username']).first()
    
    if fromdat:
        return {'Code':409}
        
    with context.app.app_context():
        inf = context.DataMod(Username=data['Username'], Password=create_hash(data['Password']), Data=encrypt({}, data['Username'], data['Password']))
        context.db.session.add(inf)
        context.db.session.commit()
    
    return {'Code':200}

def save(context, **data):
    userdat = context.cache.find(data['Hash'], data['Id'])[0]
    userinfo = context.cache.find(data['Hash'], data['Id'])[1]
    
    if userdat == None or userdat == 'you being bad?':
        return {'Code':423}
    
    if not is_serialized(data['Data']):
        return {'Code':420, 'Data':data['Data'], 'err':'Object is not json serialized'}
    
    requestdat = json.loads(data['Data'])
    
    if data['Location'] == '':
        context.cache.update(data['Hash'], data['Id'], [requestdat, userinfo])
        return {'Code':200, 'Data':requestdat}
    
    jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).update_or_create(userdat, requestdat)
    context.cache.update(data['Hash'], data['Id'], [userdat, userinfo])

    return {'Code':200, 'Data':userdat}

def delete(context, **data):
    userdat = context.cache.find(data['Hash'], data['Id'])[0]
    userinfo = context.cache.find(data['Hash'], data['Id'])[1]
    
    if userdat == None or userdat == 'you being bad?':
        return {'Code':423}
    
    if data['Location'] == '':
        context.cache.update(data['Hash'], data['Id'], [{}, userinfo])
        return {'Code':200}
    
    parsed = jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)
    
    if parsed == []:
        return {'Code':416}
    
    del [match.context for match in parsed][0].value[str([match.path for match in parsed][0])]
    context.cache.update(data['Hash'], data['Id'], [userdat, userinfo])
    
    return {'Code':200}

def logout(context, **data):
    userdat = context.cache.find(data['Hash'], data['Id'])[0]
    username, password = context.cache.find(data['Hash'], data['Id'])[1]

    if userdat == None or userdat == 'you being bad?':
        return {'Code':200}
    
    with context.app.app_context():
        fromdat = context.DataMod.query.filter_by(Username=username).first()
    
    if not fromdat:
        return {'Code':420, 'Data':userdat, 'err':'could not find user to logout'}
    
    datPass = marshal(fromdat, context.passfields)['Password']
    
    if not check_hash(datPass, password):
        return {'Code': 423}

    with context.app.app_context():
        context.db.session.delete(fromdat)
        context.db.session.add(context.DataMod(Username=username, Password=create_hash(password), Data=encrypt(userdat, username, password)))
        context.db.session.commit()
    
    return {'Code':200}

def remove(context, **data):
    username, password = context.cache.find(data['Hash'], data['Id'])[1]
            
    with context.app.app_context():
        fromdat = context.DataMod.query.filter_by(Username=username).first()
    
    if not fromdat or username == 'you being bad?':
        return {'Code':423}
    
    datPass = marshal(fromdat, context.passfields)['Password']
    
    if not check_hash(datPass, password):
        return {'Code':423}
    
    with context.app.app_context():
        context.db.session.delete(fromdat)
        context.db.session.commit()
        
    context.cache.update(data['Hash'], data['Id'], [None,(None,None)])
    
    return {'Code':200}

def login(context, **data):
    if data['Username'] == '':
        return {'Code':406}
    
    if data['Username'].isalnum() == False:
        return {'Code':406}
    
    with context.app.app_context():
        fromdat = context.DataMod.query.filter_by(Username=data['Username']).first()

    if not fromdat:
        return {'Code':404}
    
    datPass = marshal(fromdat, context.passfields)['Password']
    
    if not check_hash(datPass, data['Password']):
        return {'Code':401}
        
    if context.cache.update(data['Hash'], data['Id'], [decrypt(marshal(fromdat, context.datfields)['Data'], data['Username'], data['Password']), (data['Password'], data['Username'])])[0] == 'you being bad?':
        return {'Code':423}
    
    return {'Code':200}

def load(context, **data):
    userdat = context.cache.find(data['Hash'], data['Id'])[0]
    
    if userdat == None or userdat == 'you being bad?':
        return {'Code':423}
    
    if data['Location'] == '':
        return {'Code':202, 'Data' :userdat}
    
    parsed = jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)
    
    if parsed == []:
        return {'Code':416}
    
    return {'Code':202, 'Data':[match.value for match in parsed][0]}

def greet(context, **data):
    user = context.cache.add(data['Id'])
    
    return {'Code':101, 'Hash':user}

def leave(context, **data):
    if context.cache.delete(data['Hash'], data['Id'])[0] == 'you being bad?':
        return {'Code':423}

    return {'Code':200}

class Session():
    def __init__(self, path=None):
        self.app = Flask(__name__)
        if path == None:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
        else:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{path}/database.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        self.db = SQLAlchemy(self.app)            

        class DataMod(self.db.Model):
            Username = self.db.Column(self.db.String, nullable=False, primary_key = True)
            Password = self.db.Column(self.db.String, nullable=False)
            Data = self.db.Column(self.db.String)

            def __init__(self, Username, Password, Data):
                self.Username = Username
                self.Password = Password
                self.Data = Data

        if path == None:        
            if os.path.isfile(f'{os.getcwd()}/database.db') is False:
                with self.app.app_context():
                    self.db.create_all()

        else:
            if os.path.isfile(f'{path}/database.db') is False:
                with self.app.app_context():
                    self.db.create_all()
            
        self.datfields = {'Data': fields.Raw}
        self.passfields = {'Password': fields.String}
        self.DataMod = DataMod
        self.cache = usercache()
            
    @HandleWrapper
    def post(self, location, a ,data, **_):
        if location == 'Signup':
            return signup(self, **data)
            
        elif location == 'Save':
            return save(self, **data)

        elif location == 'Delete':
            return delete(self, **data)
            
        elif location == 'Logout':
            return logout(self, **data)
            
        elif location == 'Remove':
            return remove(self, **data)
    
        elif location == 'Login':
            return login(self, **data)
            
        elif location == 'Load':
            return load(self, **data)
                
        elif location == 'Greet':
            return greet(self, **data)
        
        elif location == 'Cert':
            return {'Code':200}
    
        elif location == 'Leave':
            return leave(self, **data)
