'''An all-in-one user authenticator and data manager'''

from sixauth.main import *

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
    
    def __init__(self, Address: str = None, Path: str = os.getcwd()):
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
        >>> auth = AuthSesh("authserver.com:5678")
        >>> # Connecting to a local database
        >>> auth = AuthSesh("/path/to/database/folder")
        """
        self._Path = Path
        self._Address = Address
        self._Id = Fernet.generate_key().hex()

        if self._Address == None:
            self._sesh = frontend_session(self._Path)
        else:
            self._sesh = backend_session(self._Address)
            
        self._requestHandle(self._sesh(code=301, id=self._Id))

    def __repr__(self):
        return f'AuthSesh({self._Path}).set_vals({self._Name}, {self._Pass})'        
    
    def __enter__(self):
        return self
    
    def __exit__(self, type, val, trace):
        self.terminate()
        tb = traceback.format_exception(type, value=val, tb=trace)
        tb = tb[:-4]
        tb = ''.join(tb)
        print(tb)
        #raise type(val) from None
        
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
    
    def save(self, Location: str, data):
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
        data = json.dumps(data)
        
        return self._requestHandle(self._sesh(code=303, location=Location, data=data, hash=self._Hash, id=self._Id))
    
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
        return self._requestHandle(self._sesh(code=308, location=Location, hash=self._Hash, id=self._Id))
    
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
        return self._requestHandle(self._sesh(code=304, location=Location, hash=self._Hash, id=self._Id))

    def login(self):
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
        self._requestHandle(self._sesh(code=305, hash=self._Hash, id=self._Id))
        return self._requestHandle(self._sesh(code=307, username=self._Name, password=self._Pass, hash=self._Hash, id=self._Id))
        
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
        return self._requestHandle(self._sesh(code=302, username=self._Name, password=self._Pass))
    
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
        return self._requestHandle(self._sesh(code=306, hash=self._Hash, id=self._Id))
    
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
        self._requestHandle(self._sesh(code=305, hash=self._Hash, id=self._Id))
        self._requestHandle(self._sesh(code=309, hash=self._Hash, id=self._Id))
        self._sesh = self._dead
    
    def _dead(self, **kwargs):
        raise AuthenticationError('Tried to call session while session is terminated')
    
    def _requestHandle(self, request):
        if request['code'] == 200:
            return self
        
        elif request['code'] == 202:
            return request['data']
        
        elif request['code'] == 201:
            self._Hash = request['hash']
        
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
            
        elif request['code'] == 420:
            raise DataError(f"An error occured during the request, here is the data we could recover: {request['data']}\n Error: {request['error']}" )
            