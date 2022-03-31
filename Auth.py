'''An all-in-one user authenticator and data manager.'''
import json
import os
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
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
    def __init__(self, Path = '\\Users\\', Name = None, Pass = None):
        self.Name = Name
        self.Pass = Pass
        self.Path = Path
        self.__User = None
        if self.Path[0] == '\\':
            self.Path = os.path.join(os.getcwd() + self.Path)
        else:
            self.Path = os.path.join(self.Path)
        if os.path.isdir(self.Path) is False:
             os.mkdir(self.Path)
        if os.path.isfile(self.Path + '\\data.json') is False:
            base = {'Accounts' :[{}]}
            with open(self.Path + '\\data.json', 'w+') as f:
                json.dump(base, f)
                f.close()
        with open(self.Path + '\\data.json', 'r') as d:
            self.jFile = json.load(d)
    def __repr__(self):
        return self.__User
    def __del__(self):
        self.Name = None
        self.Pass = None
        self.__User = None
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
        if self.Name != None:
            if self.jFile['Accounts'][0].get(self.Name) != None :
                try:
                    if self.__Decrypt(self.jFile['Accounts'][0][self.Name][0]['Password']) == hashlib.sha512((self.Pass + self.Name + self.jFile['Accounts'][0][self.Name][0]['Join Date']).encode("UTF-8")).hexdigest():
                        self.__User = self.Name
                        return True
                    else:
                        raise PasswordError('Incorrect password')
                except CryptError:
                    raise PasswordError('Incorrect password')
                except Exception as err:
                    raise err
            else:
                raise UsernameError('Username does not exists')
        else:
            raise UsernameError('Must enter username')
    def Signup(self) -> bool:
        '''
        Attempts to signup with previously specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        join = str(datetime.now())
        if self.Name != None:
            if self.jFile['Accounts'][0].get(self.Name) != None :
                raise UsernameError('Username already exists')
            else:
                if self.Name.isalnum() == True:
                    self.jFile['Accounts'][0][self.Name] = [{'Join Date': join}]
                    self.jFile['Accounts'][0][self.Name] = [{'Password':self.__Encrypt(hashlib.sha512((self.Pass + self.Name + join).encode("UTF-8")).hexdigest()).decode(), 'Data':[{}], 'Join Date': join}]
                    self.__User = self.Name
                    self.Save()
                    return True
                else:
                        raise UsernameError('Invalid username')
        else:
                raise UsernameError('Must enter username')
    def __Encrypt(self, Data):
        if self.Pass != None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes(self.jFile['Accounts'][0][self.Name][0]['Join Date'].encode()),
                iterations=390000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(bytes(self.Pass.encode())))
            fernet = Fernet(key)
            return fernet.encrypt(Data.encode())
        else:
            PasswordError('No password')
    def __Decrypt(self, Data):
        if self.Pass != None:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=bytes(self.jFile['Accounts'][0][self.Name][0]['Join Date'].encode()),
                iterations=390000,
                )
            key = base64.urlsafe_b64encode(kdf.derive(bytes(self.Pass.encode())))
            fernet = Fernet(key)
            try:
                return fernet.decrypt(Data.encode()).decode()
            except:
                raise CryptError('Bad Key')
        else:
            PasswordError('No password')