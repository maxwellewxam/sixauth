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
        self.__User = None
        rep = requests.post(self.Path + 'Shake', {'DateTime': str(datetime.now()), 'ID':hash(repr(Auth))}, verify='server-public-key.pem').json()
        self.Time = rep['DateTime']
        self.ID = rep['ID']
    def __repr__(self):
        return self.__User
    def __del__(self):
        requests.put(self.Path+'Shake', {'ID':self.ID}, verify='server-public-key.pem').json()
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
        Pass = self.__Encrypt(hashlib.sha512((self.Pass + self.Name).encode("UTF-8")).hexdigest())
        name = self.__Encrypt(self.Name)
        ret = requests.put(self.Path+'Auth', {'Username':name, 'Password':Pass, 'ID': self.ID}, verify='server-public-key.pem').json()
        if ret == 200:
            return True
    def Signup(self) -> bool:
        '''
        Attempts to signup with previously specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        Pass = self.__Encrypt(hashlib.sha512((self.Pass + self.Name).encode("UTF-8")).hexdigest())
        name = self.__Encrypt(self.Name)
        ret = requests.post(self.Path+'Auth', {'Username':name, 'Password':Pass, 'ID': self.ID}, verify='server-public-key.pem').json()
        if ret == 200:
            return True
    def __Encrypt(self, Data):
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes(self.ID.encode()),
                iterations=390000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(bytes(self.Time.encode())))
            fernet = Fernet(key)
            return fernet.encrypt(Data.encode()).decode()
    def __Decrypt(self, Data):
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes(self.ID.encode()),
                iterations=390000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(bytes(self.Time.encode())))
            fernet = Fernet(key)
            return fernet.decrypt(Data.encode()).decode()