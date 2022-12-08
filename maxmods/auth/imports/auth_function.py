import hashlib
import jsonpath_ng
import os
import json
import base64
import bcrypt

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
class SaveError(BaseException): ...


class main:
    
app = Flask(__name__)
if self._Path == None:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self._Path}/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)            

def Encrypt(Data, password, username):
    Data1 = json.dumps(Data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=390000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(Data1.encode()).decode()

def Decrypt(Data, password, username):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=390000,
        backend=default_backend()
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(Data.encode()).decode())

def encrypt_fast(message, key):
    return Fernet(key).encrypt(json.dumps(message).encode())

def decrypt_fast(message, key):
    return json.loads(Fernet(key).decrypt(message).decode())

def create_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

def check_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

class DataMod(db.Model):
    Username = db.Column(db.String, nullable=False, primary_key = True)
    Password = db.Column(db.String, nullable=False)
    Data = db.Column(db.String)

    def __init__(self, Username, Password, Data):
        self.Username = Username
        self.Password = Password
        self.Data = Data

if self._Path == None:        
    if os.path.isfile(f'{os.getcwd()}/database.db') is False:
        with app.app_context():
            db.create_all()

else:
    if os.path.isfile(f'{self._Path}/database.db') is False:
        with app.app_context():
            db.create_all()
    
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}
        
class jsonHandle:
    def __init__(self, Code):
        self.Code = Code
        
    def json(self):
        return self.Code
    
def HandleWrapper(func):
    def Wrapper(*args, **kwargs):
            return jsonHandle(func(*args, **kwargs))
    return Wrapper

def num_to_str(text):
    return text.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')

class usercache:
    def __init__(self):
        self.users = {}
        
    def add(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        jsonpath_ng.parse(num_to_str(hash)).update_or_create(self.users, encrypt_fast([None,(None,None)],id))
        
        return hash
        
    def find(self, hash, id):
        try:
            return decrypt_fast([match.value for match in jsonpath_ng.parse(num_to_str(hash)).find(self.users)][0],id)

        except InvalidToken:
            return ['you being bad?',('you being bad?','you being bad?')]
        
    def update(self, hash, id, dbdat):
        try:
            decrypt_fast([match.value for match in jsonpath_ng.parse(num_to_str(hash)).find(self.users)][0],id)
            jsonpath_ng.parse(num_to_str(hash)).update_or_create(self.users, encrypt_fast(dbdat,id))
            
        except InvalidToken:
            pass
        

    def delete(self, hash, id):
        yes = jsonpath_ng.parse(num_to_str(hash)).find(self.users)
        
        try:
            decrypt_fast([match.value for match in yes][0],id)
            del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
            return [None]
            
        except InvalidToken:
            return ['you being bad?',('you being bad?','you being bad?')]
        
class datHandle:
    cache = usercache()
    @HandleWrapper
    def post(self, location, a ,data, **_):
        if location == 'Signup':
            if data['Username'] == '':
                return {'Code':406}
            
            if data['Username'].isalnum() == False:
                return {'Code':406}
            
            with app.app_context():
                fromdat = DataMod.query.filter_by(Username=data['Username']).first()
            
            if fromdat:
                return {'Code':409}
            
            else:
                
                with app.app_context():
                    inf = DataMod(Username=data['Username'], Password=create_hash(data['Password']), Data=Encrypt({}, data['Username'], data['Password']))
                    db.session.add(inf)
                    db.session.commit()
                
                return {'Code':200}
            
        elif location == 'Save':

            userdat = self.cache.find(data['Hash'], data['Id'])[0]
            userinfo = self.cache.find(data['Hash'], data['Id'])[1]
            
            if userdat != None and userdat != 'you being bad?':
                try:
                    hmm = json.loads(data['Data'])
                    jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).update_or_create(userdat, hmm)
                
                except AttributeError as err:
                    if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                        try:
                            userdat = json.loads(data['Data'])
                        
                        except Exception as err2:
                            return {'Code':422, 'err':'No location specified or data was not a dict'}
                            
                    else:
                        raise AttributeError(err)
                        #return {'Code':202, 'Data':userdat}
                
                self.cache.update(data['Hash'], data['Id'], [userdat, userinfo])

                return {'Code':200, 'Data':userdat}

            else:
                return {'Code':423}

        elif location == 'Delete':
            
            userdat = self.cache.find(data['Hash'], data['Id'])[0]
            userinfo = self.cache.find(data['Hash'], data['Id'])[1]
            
            if userdat != None and userdat != 'you being bad?':
                try:
                    yes = jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)
                    del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
                except TypeError as err:
                        raise TypeError(err)

                except AttributeError as err:
                        raise AttributeError(err)
                    
                except IndexError as err:
                    if str(err) == 'list index out of range':
                        return {'Code':416}
                
                self.cache.update(data['Hash'], data['Id'], [userdat, userinfo])

                return {'Code':200}

            else:
                return {'Code':423}
            
        elif location == 'Logout':
            
            userdat = self.cache.find(data['Hash'], data['Id'])[0]
            username, password = self.cache.find(data['Hash'], data['Id'])[1]

            if userdat != None and userdat != 'you being bad?':
                with app.app_context():
                    fromdat = DataMod.query.filter_by(Username=username).first()
                
                if not fromdat:
                    return {'Code':420, 'Data':json.dumps(userdat)}
                
                datPass = marshal(fromdat, passfields)['Password']
                
                if check_hash(datPass, password):
                    
                    with app.app_context():
                        db.session.delete(fromdat)
                        db.session.add(DataMod(Username=username, Password=create_hash(password), Data=Encrypt(userdat, username, password)))
                        db.session.commit()
                    
                    return {'Code':200}
                
                else:
                    return {'Code':423}

            else:
                return {'Code':200}
            
        elif location == 'Remove':

            username, password = self.cache.find(data['Hash'], data['Id'])[1]
            
            with app.app_context():
                fromdat = DataMod.query.filter_by(Username=username).first()
            
            if not fromdat or username == 'you being bad?':
                return {'Code':423}

            
            datPass = marshal(fromdat, passfields)['Password']
            
            if check_hash(datPass, password):
                
                with app.app_context():
                    db.session.delete(fromdat)
                    db.session.commit()
                    
                self.cache.update(data['Hash'], data['Id'], [None,(None,None)])
                
                return {'Code':200}
            
            else:
                return {'Code':423}
        
        elif location == 'Login':
            if data['Username'] == '':
                return {'Code':406}
            
            if data['Username'].isalnum() == False:
                return {'Code':406}
            
            with app.app_context():
                fromdat = DataMod.query.filter_by(Username=data['Username']).first()
        
            if not fromdat:
                return {'Code':404}
            
            datPass = marshal(fromdat, passfields)['Password']
            
            if check_hash(datPass, data['Password']):
                
                self.cache.update(data['Hash'], data['Id'], [Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password']), (data['Password'], data['Username'])]) 
                return {'Code':200}
            
            else:
                return {'Code':401}
            
        elif location == 'Load':

            userdat = self.cache.find(data['Hash'], data['Id'])[0]
            
            if userdat != None and userdat != 'you being bad?':
                try:
                    jsonpath_expr = [match.value for match in jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)][0]
                    
                except IndexError as err:
                    if str(err) == 'list index out of range':
                        return {'Code':416}
                    
                    else:
                        raise IndexError(err)
                    
                except AttributeError as err:
                    if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                        return {'Data':userdat, 'Code':202}
                    else:
                        raise AttributeError(err)
                    
                return {'Data':jsonpath_expr, 'Code':202}
            
            else:
                return {'Code':423}
            
        elif location == 'Greet':
            user = self.cache.add(data['Id'])
            return {'Code':101, 'Hash':user}
        
        elif location == 'Cert':
            return {'Code':200}
    
        elif location == 'Leave':
            if self.cache.delete(data['Hash'], data['Id'])[0] == 'you being bad?':
                return {'Code':423}
            
            else:
                return {'Code':200}