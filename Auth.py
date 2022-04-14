'''An all-in-one user authenticator and data manager.'''

import requests
import subprocess
import sys
import os

from flask_sqlalchemy import SQLAlchemy
from flask import Flask

class LocationError(Exception): ...
class AuthenticationError(Exception): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class CryptError(Exception): ...

class Auth:
    '''
    Main class of the Auth module.
    
    Auth(Name, Pass) starts backend server on localhost
    
    Auth(Name, Pass, Path) connects to backend server at address in path

    repr(Auth) returns the current username.
    '''
    
    def __init__(self, Name: str, Pass: str, Path: str = None):
        self.Name = Name
        self.Pass = Pass
        self.Path = Path
        if self.Path == None:
            self.Path = ''
            app = Flask(__name__)
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
            app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
            db = SQLAlchemy(app)
            class DataMod(db.Model):
                Username = db.Column(db.String, nullable=False, primary_key = True)
                Password = db.Column(db.String, nullable=False)
                Data = db.Column(db.JSON)

                def __init__(self, Username, Password, Data):
                    self.Username = Username
                    self.Password = Password
                    self.Data = Data
            class seshHandle:
                def __init__(self):
                    pass
                def post(self, location, data):
                    print(location)
                def put(self, location, data):
                    print(location)
                def json(self, yes):
                    pass
            self.sesh = seshHandle()
        else:
            self.sesh = requests.Session()
            self.sesh.cert = ('ca-public-key.pem', 'ca-private-key.pem')
            try:
                rep = self.sesh.post(self.Path + 'Shake').json()
            except requests.ConnectionError as err:
                raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return self.Name
    
    def __del__(self):
        self.sesh.put(self.Path+'Shake').json()
        try:
            self.server.terminate()
        except:
            pass
    
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