'''An all-in-one user authenticator and data manager.'''
import json
import hashlib
import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import subprocess
import sys
import os
class LocationError(Exception): ...
class UsernameError(Exception): ...
class PasswordError(Exception): ...
class CryptError(Exception): ...
class Auth:
    '''
    Main class of the Auth module. Set Path to desired data.json location.  Set Name and Pass to desired values.
    
    Auth() Sets data.json location to the current working directory in 'Users' folder.
    Auth('\\\\Example\\\\') Sets data.json location to the current working directory in 'Example' folder.
    Auth('C:\\\\Users\\\\John Doe\\\\Repos\\\\') Set data.json location to 'C:\\Users\\John Doe\\Repos\\' dir.

    call repr(Auth) to retrive the current user.
    '''
    def __init__(self, Path = 'https://localhost:5678/', Name = None, Pass = None):
        self.Name = Name
        self.Pass = Pass
        self.Path = Path
        if self.Path == 'https://localhost:5678/':
            self.server = subprocess.Popen([sys.executable, os.path.join(os.getcwd(), "AuthBackend.py")], shell=True)
        self.sesh = requests.Session()
        self.sesh.cert = ('ca-public-key.pem', 'ca-private-key.pem')
        rep = self.sesh.post(self.Path + 'Shake').json()
    def __repr__(self):
        return self.Name
    def __del__(self):
        try:
            self.sesh.put(self.Path+'Shake').json()
        except:
            pass
        try:
            self.server.send_signal(signal.SIGINT)
        except:
            pass
    def Save(self, Location = None, Data = None) -> None:
        '''
        Saves specified data to specified location. Creates location if it doesn't exist.

        Auth.Save(['Loc1', 'Loc2',...], Data1) Saves Data1 to /Loc1/Loc2/
        '''
        if self.__User != None:
            try:
                if self.__Decrypt(self.jFile['Accounts'][0][self.__User][0]['Password']) == hashlib.sha512((self.Pass + self.__User + self.jFile['Accounts'][0][self.__User][0]['Join Date']).encode("UTF-8")).hexdigest():
                    if Location != None:
                        temp = self.jFile['Accounts'][0][self.__User][0]
                        Location.insert(0, 'Data')
                        for i in range(len(Location)):
                            try:
                                if i == len(Location)-1:
                                    temp[Location[i]] = self.__Encrypt(Data).decode()
                                else:
                                    newtemp = temp[Location[i]]
                            except:
                                if i == len(Location)-1:
                                    temp[Location[i]] = self.__Encrypt(Data).decode()
                                else:
                                    temp[Location[i]] = [{}]
                                    newtemp = temp[Location[i]]
                            temp = newtemp[0]
                    with open(self.Path + '\\data.json', 'w+') as f:
                        json.dump(self.jFile, f)
                else:
                    raise PasswordError('Password or Username incorrect')
            except:
                raise UsernameError('Invalid user')
        else:
            raise UsernameError('User not defined')
    def Load(self, Location) -> str:
        '''
        Loads data at specified location. Raises an exception if location doesn't exist.

        Auth.Load(['Loc1', 'Loc2',...]) Loads data in /Loc1/Loc2/
        '''
        if self.__User != None:
            try:
                if self.__Decrypt(self.jFile['Accounts'][0][self.__User][0]['Password']) == hashlib.sha512((self.Pass + self.__User + self.jFile['Accounts'][0][self.__User][0]['Join Date']).encode("UTF-8")).hexdigest():
                    temp = self.jFile['Accounts'][0][self.__User][0]['Data'][0]
                    for i in range(len(Location)):
                        try:
                            newtemp = temp[Location[i]]
                        except:
                            raise LocationError('Location does not exsist')
                        temp = newtemp[0]
                    return self.__Decrypt(newtemp)
                else:
                    raise PasswordError('Password or Username incorrect')
            except:
                raise UsernameError('Invalid user')
        else:
            raise UsernameError('User not defined')
    def Login(self) -> bool:
        '''
        Attempts to login with previously specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        #Pass = self.__Encrypt(self.Pass)
        #name = self.__Encrypt(self.Name)
        return self.requestHandle(self.sesh.put(self.Path+'Auth', {'Username':self.Name, 'Password':self.Pass}).json())
        
    def Signup(self) -> bool:
        '''
        Attempts to signup with previously specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        return self.requestHandle(self.sesh.post(self.Path+'Auth', {'Username':self.Name, 'Password':self.Pass}).json())
    def requestHandle(self, request):
        if request == 200:
            return True
        elif request == 401:
            raise PasswordError('Incorrect password')
        elif request == 404:
            raise UsernameError('Username does not exsist')
        elif request == 406:
            raise UsernameError('Invalid username')
        elif request == 409:
            raise UsernameError('Username already exists')