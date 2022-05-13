'''An all-in-one user authenticator and data manager'''
import requests
import hashlib
import jsonpath_ng
import os
import json as jjson
import base64
import warnings

from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from flask_restful import fields, marshal
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

class LocationError(Exception): ...
class AuthenticationError(Exception): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...

class AuthSesh:
    '''
    Main class of the Auth module
    
    AuthSesh() connects to database internally
    
    AuthSesh(Path) connects to backend Auth server at address in path

    repr(AuthSesh) returns the current username
    '''
    
    def __init__(self, Path: str = None, HandshakeData = None):
        self.__Path = Path
        if self.__Path == None:
            
            self.__Path = ''
            app = Flask(__name__)
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
            app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            db = SQLAlchemy(app)

            def Encrypt(Data, password, username):
                Data1 = jjson.dumps(Data)
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
                return jjson.loads(fernet.decrypt(Data.encode()).decode())
    
            class DataMod(db.Model):
                Username = db.Column(db.String, nullable=False, primary_key = True)
                Password = db.Column(db.String, nullable=False)
                Data = db.Column(db.JSON)

                def __init__(self, Username, Password, Data):
                    self.Username = Username
                    self.Password = Password
                    self.Data = Data
                    
            if os.path.isfile('database.db') is False:
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
            
            class datHandle:
                @HandleWrapper
                def post(self, location, json, **_):
                    data = json
                    if location == 'Signup':
                        if data['Username'] == '':
                            return {'Code':406}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        if fromdat:
                            return {'Code':409}
                        
                        else:
                            inf = DataMod(Username=data['Username'], Password=hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt({}, data['Username'], data['Password']))
                            db.session.add(inf)
                            db.session.commit()
                            return {'Code':200}
                        
                    elif location == 'Save':
                        if data['Username'] == '':
                            return {'Code':423}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            new = Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password'])
                            try:
                                jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).update_or_create(new, data['Data'])
                                
                            except TypeError as err:
                                if err == '\'str\' object does not support item assignment':
                                    return {'Code':422, 'err': str(err)}
                            
                            except AttributeError as err:
                                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                    try:
                                        new = jjson.loads(data['Data'])
                                    except Exception as err2:
                                        return {'Code':422, 'err': str(err2)}
                                else:
                                    raise AttributeError(err)
                            
                            db.session.delete(fromdat)
                            db.session.add(DataMod(Username=data['Username'], Password=hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt(new, data['Username'], data['Password'])))
                            db.session.commit()
                            return {'Code':200}
                        
                        else:
                            return {'Code':423}
                        
                    elif location == 'Leave':
                        return {'Code':200}

                    elif location == 'Remove':
                        if data['Username'] == '':
                            return {'Code':423}
                        if data['Username'].isalnum() == False:
                            return {'Code':423}
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        if not fromdat:
                            return {'Code':423}
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            db.session.delete(fromdat)
                            db.session.commit()
                            return {'Code':200}
                        else:
                            return {'Code':423}
                    
                    elif location == 'Login':
                        if data['Username'] == '':
                            return {'Code':406}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        if not fromdat:
                            return {'Code':404}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            return {'Code':200}
                        
                        else:
                            return {'Code':401}
                        
                    elif location == 'Load':
                        if data['Username'] == '':
                            return {'Code':423}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            farter = Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password'])
                            try:
                                jsonpath_expr = [match.value for match in jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).find(farter)][0]
                                
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                                
                                else: 
                                    raise IndexError(err)
                                
                            except AttributeError as err:
                                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                    return {'Data':farter, 'Code':202}
                                else:
                                    raise AttributeError(err)
                                
                            return {'Data':jsonpath_expr, 'Code':202}
                        
                        else:
                            return {'Code':423}
                        
                    elif location == 'Greet':
                        return {'Code':200}
                
            self.__sesh = datHandle()
        else:
            self.__sesh = requests.Session()
            
        try:
            warnings.filterwarnings('ignore')
            self.__requestHandle(self.__sesh.post(self.__Path + 'Greet', HandshakeData, verify=False).json())
            
        except requests.ConnectionError as err:
            raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return f'AuthSesh({self.__Path}).get_vals({self.__Name}, {self.__Pass})'
    
    def __del__(self, HandshakeData = None):
        self.__sesh.post(self.__Path+'Leave', HandshakeData, verify=True).json()
    
    def __cert_adder(self, server):
        with open('cacerts.pem', 'wb') as f:
            f.write(bytes(server.encode()))
        self.__sesh.verify = 'cacerts.pem'
        
    @property
    def Pass(self):
        return self.__Pass
    
    @property
    def Name(self):
        return self.__Name
    
    def get_vals(self, Name: str, Pass:str):
        '''
        Sets the desired username and password 
        '''
        self.__Name = Name
        self.__Pass = Pass
        return self
    
    def Save(self, Location: str, Data):
        '''
        Saves specified data to specified location. Creates location if it doesn't exist

        Auth.Save('Loc1/Loc2/Loc3', Data1) Saves Data1 to Loc1/Loc2/Loc3/
        '''
        if type(Data) == dict:
            Data = jjson.dumps(Data) 
        return self.__requestHandle(self.__sesh.post(self.__Path+'Save', json={'Username':self.__Name, 'Password':self.__Pass, 'Location':Location, 'Data':Data}, verify=True).json())
    def Load(self, Location: str):
        '''
        Loads data at specified location. Raises an exception if location doesn't exist

        Auth.Load('Loc1/Loc2/Loc3') Returns data in Loc1/Loc2/Loc3/
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Load', json={'Username':self.__Name, 'Password':self.__Pass, 'Location':Location}, verify=True).json())
    
    def Login(self):
        '''
        Attempts to login with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Login', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
        
    def Signup(self):
        '''
        Attempts to signup with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Signup', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
    
    def Remove_User(self):
        '''
        Attempts to remove the user with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Remove', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
    
    def __requestHandle(self, request):
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
            raise LocationError(request['err'])

        elif request['Code'] == 101:
            self.__cert_adder(request['Server'])

def Simple_Syntax():        
    from MaxMods import Menu
    class AuthMenu:
        def MainMenu(self):
            self.Menu = Menu.basicMenu('Auth Menu')
            self.Menu.add_item(1, 'Login', self.Login, 1)
            self.Menu.add_item(2, 'Signup', self.Login, 2)
            return self.Menu
        def Login(self, val):
            Name = str(input('Username: '))
            Pass = str(input('Password: '))
            self.Auth = AuthSesh().get_vals(Name, Pass)
            try:
                if val == 1:
                    self.Auth.Login()
                elif val == 2:
                    self.Auth.Signup()
                self.Menu.update_item(1, 'Logout', self.Logout)
                self.Menu.remove_item(2)
                self.Menu.add_item(2, 'Load', self.Load)
                self.Menu.add_item(3, 'Save', self.Save)
                self.Menu.Title = f'Welcome {self.Auth.Name}'
            except AuthenticationError as err:
                print(err)
                input('Press enter')
        def Load(self):
            Loc = str(input('From where: '))
            try:
                print(self.Auth.Load(Loc))
                input('Press enter')
            except LocationError as err:
                print(err)
                input('Press enter')
        def Save(self):
            Loc = str(input('To where: '))
            Dat = str(input('What to save: '))
            try:
                print(self.Auth.Save(Loc, Dat))
                input('Press enter')
            except LocationError as err:
                print(err)
                input('Press enter')
        def Logout(self):
            self.Menu.update_item(1, 'Login', self.Login, 1)
            self.Menu.update_item(2, 'Signup', self.Login, 2)
            self.Menu.remove_item(3)
            self.Menu.Title = 'Auth Menu'
    menu = AuthMenu().MainMenu()
    menu.Run()
    
if __name__ == '__main__':
    Simple_Syntax()
