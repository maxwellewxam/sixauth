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

class authClass:
    def __init__(self, path = None):
        self._Path = path
    
        self.app = Flask(__name__)
        if self._Path == None:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
        else:
            self.app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self._Path}/database.db'
        self.app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db = SQLAlchemy(self.app)            

        def encrypt(Data, password, username):
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

        def decrypt(Data, password, username):
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
            return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

        def decrypt_fast(message, key):
            return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

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
                with self.app.app_context():
                    db.create_all()

        else:
            if os.path.isfile(f'{self._Path}/database.db') is False:
                with self.app.app_context():
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
                    return [None]
                    
                except InvalidToken:
                    return ['you being bad?',('you being bad?','you being bad?')]

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
            def post(self1, location, a ,data, **_):
                if location == 'Signup':
                    if data['Username'] == '':
                        return {'Code':406}
                    
                    if data['Username'].isalnum() == False:
                        return {'Code':406}
                    
                    with self.app.app_context():
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                    
                    if fromdat:
                        return {'Code':409}
                    
                    else:
                        
                        with self.app.app_context():
                            inf = DataMod(Username=data['Username'], Password=create_hash(data['Password']), Data=encrypt({}, data['Username'], data['Password']))
                            db.session.add(inf)
                            db.session.commit()
                        
                        return {'Code':200}
                    
                elif location == 'Save':

                    userdat = self1.cache.find(data['Hash'], data['Id'])[0]
                    userinfo = self1.cache.find(data['Hash'], data['Id'])[1]
                    
                    if userdat != None and userdat != 'you being bad?':
                        try:
                            try:
                                hmm = json.loads(data['Data'])
                                jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).update_or_create(userdat, hmm)
                            
                            except AttributeError as err:
                                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                    userdat = json.loads(data['Data'])
                                        
                                else:
                                    raise AttributeError(err)
                            
                            self1.cache.update(data['Hash'], data['Id'], [userdat, userinfo])

                            return {'Code':200, 'Data':userdat}

                        except Exception as err:
                            return {'Code':420, 'Data':userdat, 'err':err}
                        
                    else:
                        return {'Code':423}

                elif location == 'Delete':
                    
                    userdat = self1.cache.find(data['Hash'], data['Id'])[0]
                    userinfo = self1.cache.find(data['Hash'], data['Id'])[1]
                    
                    if userdat != None and userdat != 'you being bad?':
                        try:
                            try:
                                yes = jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)
                                del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
                                
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                            
                            self1.cache.update(data['Hash'], data['Id'], [userdat, userinfo])

                            return {'Code':200}
                        
                        except Exception as err:
                            return {'Code':420, 'Data':userdat, 'err':err}

                    else:
                        return {'Code':423}
                    
                elif location == 'Logout':
                    
                    userdat = self1.cache.find(data['Hash'], data['Id'])[0]
                    username, password = self1.cache.find(data['Hash'], data['Id'])[1]

                    if userdat != None and userdat != 'you being bad?':
                        try:
                            with self.app.app_context():
                                fromdat = DataMod.query.filter_by(Username=username).first()
                            
                            if not fromdat:
                                return {'Code':420, 'Data':json.dumps(userdat)}
                            
                            datPass = marshal(fromdat, passfields)['Password']
                            
                            if check_hash(datPass, password):
                                
                                with self.app.app_context():
                                    db.session.delete(fromdat)
                                    db.session.add(DataMod(Username=username, Password=create_hash(password), Data=encrypt(userdat, username, password)))
                                    db.session.commit()
                                
                                return {'Code':200}
                            
                            else:
                                return {'Code':423}
                        
                        except Exception as err:
                            return {'Code':420, 'Data':userdat, 'err':err}

                    else:
                        return {'Code':200}
                    
                elif location == 'Remove':

                    username, password = self1.cache.find(data['Hash'], data['Id'])[1]
                    
                    with self.app.app_context():
                        fromdat = DataMod.query.filter_by(Username=username).first()
                    
                    if not fromdat or username == 'you being bad?':
                        return {'Code':423}
                    
                    datPass = marshal(fromdat, passfields)['Password']
                    
                    if check_hash(datPass, password):
                        
                        with self.app.app_context():
                            db.session.delete(fromdat)
                            db.session.commit()
                            
                        self1.cache.update(data['Hash'], data['Id'], [None,(None,None)])
                        
                        return {'Code':200}
                    
                    else:
                        return {'Code':423}
                
                elif location == 'Login':
                    if data['Username'] == '':
                        return {'Code':406}
                    
                    if data['Username'].isalnum() == False:
                        return {'Code':406}
                    
                    with self.app.app_context():
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                
                    if not fromdat:
                        return {'Code':404}
                    
                    datPass = marshal(fromdat, passfields)['Password']
                    
                    if check_hash(datPass, data['Password']):
                        
                        if self1.cache.update(data['Hash'], data['Id'], [decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password']), (data['Password'], data['Username'])])[0] != 'you being bad?':
                            return {'Code':200}
                        
                        else:
                            return {'Code':423}
                    
                    else:
                        return {'Code':401}
                    
                elif location == 'Load':

                    userdat = self1.cache.find(data['Hash'], data['Id'])[0]
                    
                    if userdat != None and userdat != 'you being bad?':
                        try:
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
                        
                        except Exception as err:
                            return {'Code':420, 'Data':userdat, 'err':err}
                    
                    else:
                        return {'Code':423}

                elif location == 'Greet':
                    try:
                        user = self1.cache.add(data['Id'])
                        return {'Code':101, 'Hash':user}
                    except Exception as err:
                        return {'Code':420, 'Data':None, 'err':err}
                
                elif location == 'Cert':
                    return {'Code':200}
            
                elif location == 'Leave':
                    if self1.cache.delete(data['Hash'], data['Id'])[0] == 'you being bad?':
                        return {'Code':423}
                    
                    else:
                        return {'Code':200}
                    
        self.Session = datHandle