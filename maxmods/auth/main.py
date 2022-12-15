'''An all-in-one user authenticator and data manager'''

from maxmods.auth.imports import *

class AuthSesh:
    """Main class of the Auth module.
    
    AuthSesh() connects to database internally\n
    AuthSesh(Address) connects to backend Auth server at address in path\n
    AuthSesh(Path) connects to database internally to database at Path location\n
    repr(AuthSesh) returns the current username\n

    The docstrings for this class were written by OpenAI.

    Examples
    --------
    >>> # Using a context manager
    >>> with AuthSesh() as auth:
    >>>     auth.set_vals("username", "password")
    >>>     auth.login()
    >>>     user_data = auth.load("user_data/profile")
    This will create an `AuthSesh` instance that connects to a local database, log in with the provided username and password, and load the data from the location "user_data/profile" on the server. The `AuthSesh` instance will be terminated when exiting the context manager.\n

    >>> # Without a context manager
    >>> auth = AuthSesh()
    >>> auth.set_vals("username", "password")
    >>> auth.login()
    >>> user_data = auth.load("user_data/profile")
    >>> auth.terminate()
    This will create an `AuthSesh` instance that connects to a local database, log in with the provided username and password, and load the data from the location "user_data/profile" on the server. The `AuthSesh` instance will be terminated manually by calling the `terminate` method.
    """
    def __init__(self, Address: str = None, Path: str = None):
        """Initializes the `AuthSesh` instance.

        This method can connect to a backend authentication server or a database depending on the arguments provided.

        Parameters
        ----------
        Address : str, optional
            The address of the backend authentication server. If `Address` is provided, the `AuthSesh` instance will connect to the server at the specified address. If `Address` is not provided, the `AuthSesh` instance will connect to a local database instead.
        Path : str, optional
            The path to the local database. This argument is only used if `Address` is not provided.

        Returns
        -------
        object
            The newly created `AuthSesh` instance.

        Raises
        ------
        LocationError
            If the `AuthSesh` instance fails to connect to the backend authentication server or the local database.

        Examples
        --------
        >>> # Connecting to a backend server
        >>> auth = AuthSesh("https://authserver.com")
        >>> # Connecting to a local database
        >>> auth = AuthSesh("/path/to/database/folder")
        """
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
            self._requestHandle(self._sesh.post(self._Path + 'create_session', None, {'id':self._Id}, verify=True).json())
            
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
        """The password set for the current `AuthSesh` instance.

        Returns
        -------
        str
            The password set for the `AuthSesh` instance.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> print(auth.Pass)
        This will print the password set for the `AuthSesh` instance.
        """
        return self._Pass
    
    @property
    def Name(self):
        """The username set for the current `AuthSesh` instance.

        Returns
        -------
        str
            The username set for the `AuthSesh` instance.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> print(auth.Name)
        This will print the username set for the `AuthSesh` instance.
        """
        return self._Name
    
    def set_vals(self, Name: str, Pass:str):
        """Sets the username and password for the current `AuthSesh` instance.

        Parameters
        ----------
        Name : str
            The desired username.
        Pass : str
            The password associated with the given username.

        Returns
        -------
        AuthSesh
            The `AuthSesh` instance with the updated username and password.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        This will set the username and password for the `AuthSesh` instance to "username" and "password" respectively.
        """
        self._Name = Name
        self._Pass = Pass
        return self
    
    def save(self, Location: str, Data):
        """Saves the given data to the specified location on the backend authentication server.

        If the specified location does not exist, it will be created.
        If no location is specified and the data is a dictionary, it will replace the entire database with the given dictionary.
        
        Raises a `DataError` if it fails to save the data to the specified location.

        Parameters
        ----------
        Location : str
            The location on the backend server where the data should be saved.
        Data : object
            The data to be saved to the specified location.

        Returns
        -------
        object
            The response from the server indicating whether the data was successfully saved.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        >>> auth.save("user_data/profile", {"name": "John Doe", "age": 30})
        This will save the dictionary {"name": "John Doe", "age": 30} to the location "user_data/profile" on the backend server.
        """
        Data = json.dumps(Data)
        
        return self._requestHandle(self._sesh.post(self._Path+'save_data', None, {'location':Location, 'data':Data, 'hash':self._Hash, 'id':self._Id}, verify=True).json())
    def load(self, Location = ''):
        """Loads data from the specified location on the backend authentication server.

        Raises a `LocationError` if the specified location does not exist. Rasies `DataError` if there is an error loading the data from the server.

        Parameters
        ----------
        Location : str, optional
            The location on the backend server from which to load data. If no location is specified, the entire database will be loaded.

        Returns
        -------
        object
            The data loaded from the specified location on the backend server.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        >>> user_data = auth.load("user_data/profile")
        This will load the data from the location "user_data/profile" on the backend server and store it in the `user_data` variable.
        """
        return self._requestHandle(self._sesh.post(self._Path+'load_data', None, {'location':Location, 'hash':self._Hash, 'id':self._Id}, verify=True).json())
    
    def delete(self, Location: str):
        """Deletes the data at the specified location on the backend authentication server.

        Raises a `LocationError` if the specified location does not exist. Rasies `DataError` if there is an error deleting the data from the server.

        Parameters
        ----------
        Location : str
            The location on the backend server from which to delete data.

        Returns
        -------
        object
            The response from the server indicating whether the data was successfully deleted.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        >>> auth.delete("user_data/profile")
        This will delete the data at the location "user_data/profile" on the backend server.
        """
        return self._requestHandle(self._sesh.post(self._Path+'delete_user', None, {'location':Location, 'hash':self._Hash, 'id':self._Id}, verify=True).json())

    def login(self) -> None:
        """Attempts to log in with the username and password set for the current `AuthSesh` instance.

        Raises a `UsernameError` or `PasswordError`, for example if the username or password is incorrect.

        Returns
        -------
        object
            The response from the server indicating whether the login was successful.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        This will attempt to log in with the username and password set for the `AuthSesh` instance.
        """
        self._requestHandle(self._sesh.post(self._Path+ 'log_out', None, {'hash':self._Hash, 'id':self._Id}, verify=True).json())
        return self._requestHandle(self._sesh.post(self._Path+'log_in', None, {'username':self._Name, 'password':self._Pass, 'hash':self._Hash, 'id':self._Id}, verify=True).json())
        
    def signup(self):
        """Attempts to sign up with the username and password set for the current `AuthSesh` instance.

        Raises a `UsernameError` or `PasswordError` if the signup fails, for example if the username is already in use or the password is wrong.

        Returns
        -------
        object
            The response from the server indicating whether the signup was successful.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.signup()
        This will attempt to sign up with the username and password set for the `AuthSesh` instance.
        """
        return self._requestHandle(self._sesh.post(self._Path+'sign_up', None, {'username':self._Name, 'password':self._Pass}, verify=True).json())
    
    def remove(self):
        """Attempts to remove the user with the username and password set for the current `AuthSesh` instance.

        Raises a `AuthenticationError` if the removal fails, for example if the username or password is incorrect.

        Returns
        -------
        object
            The response from the server indicating whether the user was successfully removed.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.remove()
        This will attempt to remove the user with the username and password set for the `AuthSesh` instance.
        """
        return self._requestHandle(self._sesh.post(self._Path+'remove_account', None, {'hash':self._Hash, 'id':self._Id}, verify=True).json())
    
    def terminate(self):
        """Terminates the current `AuthSesh` instance.

        Returns
        -------
        object
            The response from the server indicating whether the `AuthSesh` instance was successfully terminated.

        Examples
        --------
        >>> auth = AuthSesh()
        >>> auth.set_vals("username", "password")
        >>> auth.login()
        >>> auth.terminate()
        This will log in with the username and password set for the `AuthSesh` instance, and then terminate the `AuthSesh` instance.
        """
        self._requestHandle(self._sesh.post(self._Path+ 'log_out', None, {'hash':self._Hash, 'id':self._Id}, verify=True).json())
        self._requestHandle(self._sesh.post(self._Path+'end_session', None, {'hash':self._Hash, 'id':self._Id}, verify=True).json())

    
    def _requestHandle(self, request):
        if request['code'] == 200:
            return self
        
        elif request['code'] == 202:
            return request['data']
        
        elif request['code'] == 416:
            raise LocationError('Loaction does not exist')
        
        elif request['code'] == 401:
            raise PasswordError('Incorrect password')
        
        elif request['code'] == 404:
            raise UsernameError('Username does not exist')
        
        elif request['code'] == 406:
            raise UsernameError('Invalid username')
        
        elif request['code'] == 409:
            raise UsernameError('Username already exists')
        
        elif request['code'] == 423:
            raise AuthenticationError('Failed to authenticate user')

        elif request['code'] == 101:
            self._Hash = request['hash']
        
        elif request['code'] == 102:
            self._certadder(request['server'])
            
        elif request['code'] == 420:
            raise DataError(f"An error occured during the request, here is the data we could recover: {request['data']}/n Error: {request['error']}" )
            