'''An all-in-one user authenticator and data manager.'''

import requests
import hashlib
import jsonpath_ng
import base64

from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class LocationError(Exception): ...
class AuthenticationError(Exception): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...

class Auth:
    '''
    Main class of the Auth module.
    
    Auth() connects to database internally
    
    Auth(Path) connects to backend server at address in path

    repr(Auth) returns the current username.
    '''
    
    def __init__(self, Path: str = None):
        self.Path = Path
        if self.Path == None:
            
            self.Path = ''
            app = Flask(__name__)
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
            app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            db = SQLAlchemy(app)
            
            def Encrypt(Data, password, username):
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=bytes(username.encode()),
                    iterations=390000,
                    )
                key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
                fernet = Fernet(key)
                return fernet.encrypt(Data.encode()).decode()

            def Decrypt(Data, password, username):
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=bytes(username.encode()),
                    iterations=390000,
                    )
                key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
                fernet = Fernet(key)
                return fernet.decrypt(Data.encode()).decode()
    
            class DataMod(db.Model):
                Username = db.Column(db.String, nullable=False, primary_key = True)
                Password = db.Column(db.String, nullable=False)
                Data = db.Column(db.JSON)

                def __init__(self, Username, Password, Data):
                    self.Username = Username
                    self.Password = Password
                    self.Data = Data
            
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
            
            class datHandle:
                @HandleWrapper
                def post(self, location, data):
                    if location == 'Auth':
                        fromuser = data
                        if fromuser['Username'] == '':
                            return {'Code':406}
                        
                        if fromuser['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
                        if fromdat:
                            return {'Code':409}
                        
                        else:
                            inf = DataMod(Username=fromuser['Username'], Password=hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest(), Data={})
                            db.session.add(inf)
                            db.session.commit()
                            return {'Code':200}
                        
                    elif location == 'Data':
                        fromuser = data
                        if fromuser['Username'] == '':
                            return {'Code':423}
                        
                        if fromuser['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            new = dict(marshal(fromdat, datfields)['Data'])
                            try:
                                jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-')).update_or_create(new, Encrypt(data['Data'], data['Username'], data['Password']))
                                
                            except TypeError as err:
                                if err == '\'str\' object does not support item assignment':
                                    return {'Code':422}
                                
                            db.session.delete(fromdat)
                            db.session.add(DataMod(Username=fromuser['Username'], Password=hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest(), Data=new))
                            db.session.commit()
                            return {'Code':200}
                        
                        else:
                            return {'Code':423}
                        
                    elif location == 'Shake':
                        return {'Code':200}
                    
                @HandleWrapper
                def put(self, location, data):
                    if location == 'Auth':
                        fromuser = data
                        if fromuser['Username'] == '':
                            return {'Code':406}
                        
                        if fromuser['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
                        if not fromdat:
                            return {'Code':404}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            return {'Code':200}
                        
                        else:
                            return {'Code':401}
                        
                    elif location == 'Data':
                        fromuser = data
                        if fromuser['Username'] == '':
                            return {'Code':423}
                        
                        if fromuser['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            farter = dict(marshal(fromdat, datfields)['Data'])
                            try:
                                jsonpath_expr = Decrypt([match.value for match in jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-')).find(farter)][0], data['Username'], data['Password'])
                                
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                                
                                else: 
                                    raise IndexError(err)
                                
                            return {'Data':jsonpath_expr, 'Code':202}
                        
                        else:
                            return {'Code':423}
                        
                    elif location == 'Shake':
                        return {'Code':200}
                
            self.sesh = datHandle()
        else:
            self.sesh = requests.Session()
            self.sesh.cert = ('ca-public-key.pem', 'ca-private-key.pem')
            
        try:
            self.sesh.post(self.Path + 'Shake').json()
            
        except requests.ConnectionError as err:
            raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return self.Name
    
    def __del__(self):
        self.sesh.put(self.Path+'Shake', 'JOE MOMMA').json()
        
    def set_auth_values(self, Name: str, Pass:str):
        '''
        Sets the Desired username and password 
        '''
        self.Name = Name
        self.Pass = Pass
    
    def Save(self, Location: str, Data: str) -> bool:
        '''
        Saves specified data to specified location. Creates location if it doesn't exist.

        Auth.Save('Loc1/Loc2/Loc3', Data1) Saves Data1 to Loc1/Loc2/Loc3/
        '''
        return self.requestHandle(self.sesh.post(self.Path+'Data', {'Username':self.Name, 'Password':self.Pass, 'Location':Location, 'Data':Data}).json())
    
    def Load(self, Location: str) -> str:
        '''
        Loads data at specified location. Raises an exception if location doesn't exist.

        Auth.Load('Loc1/Loc2/Loc3') Returns data in Loc1/Loc2/Loc3/
        '''
        return self.requestHandle(self.sesh.put(self.Path+'Data', {'Username':self.Name, 'Password':self.Pass, 'Location':Location}).json())
    
    def Login(self) -> bool:
        '''
        Attempts to login with specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        return self.requestHandle(self.sesh.put(self.Path+'Auth', {'Username':self.Name, 'Password':self.Pass}).json())
        
    def Signup(self) -> bool:
        '''
        Attempts to signup with specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        return self.requestHandle(self.sesh.post(self.Path+'Auth', {'Username':self.Name, 'Password':self.Pass}).json())
    
    def requestHandle(self, request):
        if request['Code'] == 200:
            return True
        
        elif request['Code'] == 202:
            return request['Data']
        
        elif request['Code'] == 416:
            raise LocationError('Loaction does not exist')
        
        elif request['Code'] == 401:
            raise PasswordError('Incorrect password')
        
        elif request['Code'] == 404:
            raise UsernameError('Username does not exist')
        
        elif request['Code'] == 406:
            raise UsernameError('Invalid username')
        
        elif request['Code'] == 409:
            raise UsernameError('Username already exists')
        
        elif request['Code'] == 423:
            raise AuthenticationError('Failed to authenticate user')
        
        elif request['Code'] == 422:
            raise LocationError('Cannot access type \'str\'')