'''An all-in-one user authenticator and data manager.'''

import requests
import subprocess
import sys
import os

class LocationError(Exception): ...
class AuthenticationError(Exception): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...
class CryptError(Exception): ...

class Auth:
    '''
    Main class of the Auth module. Set Path to desired data.json location.  Set Name and Pass to desired values.
    
    Auth() Sets data.json location to the current working directory in 'Users' folder.
    Auth('\\\\Example\\\\') Sets data.json location to the current working directory in 'Example' folder.
    Auth('C:\\\\Users\\\\John Doe\\\\Repos\\\\') Set data.json location to 'C:\\Users\\John Doe\\Repos\\' dir.

    call repr(Auth) to retrive the current user.
    '''
    
    def __init__(self, Path = None, Name = None, Pass = None):
        self.Name = Name
        self.Pass = Pass
        self.Path = Path
        if self.Path == None:
            self.Path = 'https://localhost:5678/'
            self.server = subprocess.Popen([sys.executable, os.path.join(os.getcwd(), "AuthBackend.py")], shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        self.sesh = requests.Session()
        self.sesh.cert = ('ca-public-key.pem', 'ca-private-key.pem')
        rep = self.sesh.post(self.Path + 'Shake').json()
        
    def __repr__(self):
        return self.Name
    
    def __del__(self):
        try:
            self.sesh.put(self.Path+'Shake').json()
        except:
            print('dont care about this rn')
        try:
            self.server.terminate()
        except:
            print('couldnt close this')
            
    def Save(self, Location, Data) -> bool:
        '''
        Saves specified data to specified location. Creates location if it doesn't exist.

        Auth.Save(['Loc1', 'Loc2',...], Data1) Saves Data1 to /Loc1/Loc2/
        '''
        return self.requestHandle(self.sesh.post(self.Path+'Data', {'Username':self.Name, 'Password':self.Pass, 'Location':Location, 'Data':Data}).json())
    
    def Load(self, Location) -> str:
        '''
        Loads data at specified location. Raises an exception if location doesn't exist.

        Auth.Load(['Loc1', 'Loc2',...]) Returns data in /Loc1/Loc2/
        '''
        return self.requestHandle(self.sesh.put(self.Path+'Data', {'Username':self.Name, 'Password':self.Pass, 'Location':Location}).json())
    
    def Login(self) -> bool:
        '''
        Attempts to login with previously specified Auth.Name and Auth.Pass values.
        
        Raises an exception if it fails.
        '''
        return self.requestHandle(self.sesh.put(self.Path+'Auth', {'Username':self.Name, 'Password':self.Pass}).json())
        
    def Signup(self) -> bool:
        '''
        Attempts to signup with previously specified Auth.Name and Auth.Pass values.
        
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