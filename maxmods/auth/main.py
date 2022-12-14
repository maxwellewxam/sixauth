'''An all-in-one user authenticator and data manager'''

from maxmods.auth.imports import *

class AuthSesh:
    '''
    This class provides a set of methods for interacting with an authentication and data storage service.
    
    Args:
        Address (str): The address of the server to connect to.
        Path (str): The path to a local database.
        
    Attributes:
        _Path (str): The path to the local database.
        _Address (str): The address of the server.
        _Id (str): A unique identifier for the session.
        _sesh (Session): A session object for making requests to the server.
        _Name (str): The username for the session.
        _Pass (str): The password for the session.
        _Hash (str): A hash value used for authentication.
        
    Methods:
        set_vals: Sets the username and password for the session.
        save: Saves data to the specified location on the server or local database.
        load: Loads data from the specified location on the server or local database.
        delete: Deletes data at the specified location on the server or local database.
        login: Attempts to log in to the server using the specified username and password.
        signup: Attempts to create a new account on the server with the specified username and password.
        terminate: Ends the session and logs out of the server.

    Usage:
        Without Context Manager:
            # Connect to the server at the specified address\n
            auth = AuthSesh(Address='http://my-auth-server.com/')
            
            # Set the username and password for the session\n
            auth.set_vals(Name='myusername', Pass='mypassword')
            
            # Attempt to log in to the server\n
            auth.login()
            
            # Save some data to the server\n
            auth.save(Location='mydata/myfolder', Data={'key': 'value'})
        
            # Load the data that we just saved\n
            data = auth.load(Location='mydata/myfolder')\n
            print(data) # Should print: {'key': 'value'}

            # Delete the data that we saved\n
            auth.delete(Location='mydata/myfolder')
            
            # Log out of the session\n
            auth.terminate()
            
        With Context Manager:
            # Connect to the server at the specified address \n
            with AuthSesh(Address='http://my-auth-server.com/') as auth:
            
                # Set the username and password for the session \n
                auth.set_vals(Name='myusername', Pass='mypassword')
                
                # Attempt to log in to the server\n
                auth.login()
                
                # Save some data to the server \n
                auth.save(Location='mydata/myfolder', Data={'key': 'value'})
            
                # Load the data that we just saved \n
                data = auth.load(Location='mydata/myfolder')\n
                print(data) # Should print: {'key': 'value'}

                # Delete the data that we saved \n
                auth.delete(Location='mydata/myfolder')
    '''
    
    def __init__(self, Address: str = None, Path: str = None):
        self._Path = Path
        self._Address = Address
        self._Id = Fernet.generate_key().hex()

        if self._Address == None:
            self._sesh = Session(self._Path)
            self._Path = ''
        else:
            self._sesh = requests.Session()
            self._Path = self._Address
        try:
            warnings.filterwarnings('ignore')
            self._requestHandle(self._sesh.post(self._Path + 'Cert', None, {}, verify=False).json())
            self._requestHandle(self._sesh.post(self._Path + 'Greet', None, {'Id':self._Id}, verify=True).json())
            
        except requests.ConnectionError as err:
            raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return f'AuthSesh({self._Path}).set_vals({self._Name}, {self._Pass})'        
    
    def __enter__(self):
        return self
    
    def __exit__(self, type, val, trace):
        if str(val) != 'Username does not exist':
            self.terminate()
        

    def _certadder(self, server):
        with open('cacerts.pem', 'wb') as f:
            f.write(bytes(server.encode()))
        self._sesh.verify = 'cacerts.pem'
        
    @property
    def Pass(self):
        return self._Pass
    
    @property
    def Name(self):
        return self._Name
    
    def set_vals(self, Name: str, Pass:str):
        '''
        Sets the desired username and password 
        '''
        self._Name = Name
        self._Pass = Pass
        return self
    
    def save(self, Location: str, Data):
        '''
        Saves data to the specified location. Creates location if it doesn't exist

        If no location is specified and the data is a Dict, it will replace everythin with the Dict

        rasies LocationError if it fails

        Auth.Save('Loc1/Loc2/Loc3', 'Data') 
        '''
        Data = json.dumps(Data)
        
        return self._requestHandle(self._sesh.post(self._Path+'Save', None, {'Location':Location, 'Data':Data, 'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
    def load(self, Location = ''):
        '''
        Loads data at specified location. Raises an exception if location doesn't exist

        Auth.Load('Loc1/Loc2/Loc3') Returns data in Loc1/Loc2/Loc3/
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Load', None, {'Location':Location, 'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
    
    def delete(self, Location: str):
        '''
        Deletes data at specified location. Raises an exception if location doesn't exist.

        Auth.Delete('Loc1/Loc2/Loc3') Deletes data in Loc1/Loc2/Loc3/
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Delete', None, {'Location':Location, 'Hash':self._Hash, 'Id':self._Id}, verify=True).json())

    def login(self) -> None:
        '''
        Attempts to log in to the server using the username and password specified
        in the `set_vals` method. Raises an exception if the login fails.
        '''
        self._requestHandle(self._sesh.post(self._Path+ 'Logout', None, {'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
        return self._requestHandle(self._sesh.post(self._Path+'Login', None, {'Username':self._Name, 'Password':self._Pass, 'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
        
    def signup(self):
        '''
        Attempts to signup with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Signup', None, {'Username':self._Name, 'Password':self._Pass}, verify=True).json())
    
    def remove(self):
        '''
        Attempts to remove the user with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Remove', None, {'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
    
    def terminate(self):
        '''
        Closes connection to backend and saves cache
        
        if you do not manually call this, you are at the mercy of the garbage collector (unless you are using the context manager!)
        '''
        self._requestHandle(self._sesh.post(self._Path+ 'Logout', None, {'Hash':self._Hash, 'Id':self._Id}, verify=True).json())
        self._requestHandle(self._sesh.post(self._Path+'Leave', None, {'Hash':self._Hash, 'Id':self._Id}, verify=True).json())

    
    def _requestHandle(self, request):
        if request['Code'] == 200:
            return self
        
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

        elif request['Code'] == 101:
            self._Hash = request['Hash']
        
        elif request['Code'] == 102:
            self._certadder(request['Server'])
            
        elif request['Code'] == 420:
            raise DataError(f"An error occured during the request, here is the data we could recover: {request['Data']}/n Error: {request['err']}" )
            