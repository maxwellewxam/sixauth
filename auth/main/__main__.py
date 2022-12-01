'''An all-in-one user authenticator and data manager'''

from maxmods.imports.authimports import *

class AuthSesh:
    '''
    Main class of the Auth module
    
    AuthSesh() connects to database internally
    
    AuthSesh(Address) connects to backend Auth server at address in path

    AuthSesh(Path) connects to database internally to database at Path location

    repr(AuthSesh) returns the current username
    '''
    
    def __init__(self, Address: str = None, Path: str = None):
        self._Path = Path
        self._Address = Address
        self._active = True
        self._removed = True
        if self._Address == None:
            
            app = Flask(__name__)
            if self._Path == None:
                app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
            else:
                app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self._Path}/database.db'
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
                Data = db.Column(db.String)

                def __init__(self, Username, Password, Data):
                    self.Username = Username
                    self.Password = Password
                    self.Data = Data
            
            if self._Path == None:        
                if os.path.isfile(f'{os.getcwd()}/database.db') is False:
                    with app.app_context():
                        db.createall()

            else:
                if os.path.isfile(f'{self._Path}/database.db') is False:
                    with app.app_context():
                        db.createall()
                
            datfields = {'Data': fields.Raw}
            passfields = {'Password': fields.String}
            
            class usercache:
                def __init__(self):
                    self.users = {}
                    
                def add(self, id):
                    hash = hashlib.sha512((id).encode("UTF-8")).hexdigest()
                    jsonpath_ng.parse(hash).update_or_create(self.users, [])
                    
            class jsonHandle:
                def __init__(self, Code):
                    self.Code = Code
                    
                def json(self):
                    return self.Code
                
            def HandleWrapper(func):
                def Wrapper(*args, **kwargs):
                        return jsonHandle(func(*args, **kwargs))
                return Wrapper
            
            def num_to_str(text):
                return text.replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')
            
            class usercache:
                def __init__(self):
                    self.users = {}
                    
                def add(self, id):
                    hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
                    jsonpath_ng.parse(num_to_str(hash)).update_or_create(self.users, [None,(None,None)])
                    return hash
                    
                def find(self, hash):
                    return [match.value for match in jsonpath_ng.parse(num_to_str(hash)).find(self.users)][0]
                
                def update(self, hash, dbdat):
                    jsonpath_ng.parse(num_to_str(hash)).update_or_create(self.users, dbdat)
                    
                def delete(self, hash):
                    yes = jsonpath_ng.parse(num_to_str(hash)).find(self.users)
                    del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
            
            class datHandle:
                cache = usercache()
                @HandleWrapper
                def post(self, location, json, **_):
                    data = json
                    if location == 'Signup':
                        if data['Username'] == '':
                            return {'Code':406}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        
                        if fromdat:
                            return {'Code':409}
                        
                        else:
                            
                            with app.app_context():
                                inf = DataMod(Username=data['Username'], Password=hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt({}, data['Username'], data['Password']))
                                db.session.add(inf)
                                db.session.commit()
                            
                            return {'Code':200}
                        
                    elif location == 'Save':

                        userdat = self.cache.find(data['Hash'])[0]
                        userinfo = self.cache.find(data['Hash'])[1]
                        
                        if userdat != None:
                            try:
                                hmm = jjson.loads(data['Data'])
                                jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).update_or_create(userdat, hmm)
                            
                            except AttributeError as err:
                                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                    try:
                                        #userdat = jjson.loads(data['Data'])
                                        pass
                                    
                                    except Exception as err2:
                                        return {'Code':422, 'err':'No location specified or data was not a dict'}
                                        
                                else:
                                    raise AttributeError(err)
                            
                            self.cache.update(data['Hash'], [userdat, userinfo])

                            return {'Code':200, 'Data':userdat}

                        else:
                            return {'Code':423}

                    elif location == 'Delete':
                        
                        userdat = self.cache.find(data['Hash'])[0]
                        userinfo = self.cache.find(data['Hash'])[1]
                        
                        if userdat != None:
                            try:
                                yes = jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)
                                del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
                            except TypeError as err:
                                    raise TypeError(err)

                            except AttributeError as err:
                                    raise AttributeError(err)
                                
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                            
                            self.cache.update(data['Hash'], [userdat, userinfo])

                            return {'Code':200}

                        else:
                            return {'Code':423}
                        
                    elif location == 'Logout':
                        
                        userdat = self.cache.find(data['Hash'])[0]
                        username, password = self.cache.find(data['Hash'])[1]

                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=username).first()
                        
                        if not fromdat:
                            return {'Code':420}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((password + username).encode("UTF-8")).hexdigest()
                        
                        if userPass == datPass:
                            
                            with app.app_context():
                                 db.session.delete(fromdat)
                                 db.session.add(DataMod(Username=username, Password=hashlib.sha512((password + username).encode("UTF-8")).hexdigest(), Data=Encrypt(userdat, username, password)))
                                 db.session.commit()
                            
                            return {'Code':200}
                        
                        else:
                            return {'Code':423}

                    elif location == 'Remove':

                        username, password = self.cache.find(data['Hash'])[1]
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=username).first()
                        
                        if not fromdat:
                            return {'Code':423}

                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((password + username).encode("UTF-8")).hexdigest()
                        
                        if userPass == datPass:
                            
                            with app.app_context():
                                db.session.delete(fromdat)
                                db.session.commit()
                            
                            return {'Code':204}
                        
                        else:
                            return {'Code':423}
                    
                    elif location == 'Login':
                        if data['Username'] == '':
                            return {'Code':406}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':406}
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                    
                        if not fromdat:
                            return {'Code':404}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        
                        if userPass == datPass:
                            
                            self.cache.update(data['Hash'], [Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password']), (data['Password'], data['Username'])]) 
                            
                            return {'Code':200}
                        
                        else:
                            return {'Code':401}
                        
                    elif location == 'Load':

                        userdat = self.cache.find(data['Hash'])[0]
                        
                        if userdat != None:
                            try:
                                jsonpath_expr = [match.value for match in jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).find(userdat)][0]
                                
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                                
                                else: 
                                    raise IndexError(err)
                                
                            except AttributeError as err:
                                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                    return {'Data':userdat, 'Code':202}
                                else:
                                    raise AttributeError(err)
                                
                            return {'Data':jsonpath_expr, 'Code':202}
                        
                        else:
                            return {'Code':423}
                        
                    elif location == 'Greet':
                        
                        user = self.cache.add(data['Id'])
                        return {'Code':101, 'Hash':user}
                    
                    elif location == 'Cert':
                        return {'Code':200}
                
                    elif location == 'Leave':
                        self.cache.delete(data['Hash'])

                        return {'Code':200}
                
            self._sesh = datHandle()
            self._Path = ''
        else:
            self._sesh = requests.Session()
            self._Path = self._Address
        try:
            warnings.filterwarnings('ignore')
            self._requestHandle(self._sesh.post(self._Path + 'Cert', json={}, verify=False).json())
            self._requestHandle(self._sesh.post(self._Path + 'Greet', json={'Id':random.randint(100000, 999999)}, verify=True).json())
            
        except requests.ConnectionError as err:
            raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return f'AuthSesh({self._Path}).set_vals({self._Name}, {self._Pass})'        
    
    def __del__(self):
         if self._active:
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
        Data = jjson.dumps(Data)
        
        return self._requestHandle(self._sesh.post(self._Path+'Save', json={'Location':Location, 'Data':Data, 'Hash':self._Hash}, verify=True).json())
    def load(self, Location = ''):
        '''
        Loads data at specified location. Raises an exception if location doesn't exist

        Auth.Load('Loc1/Loc2/Loc3') Returns data in Loc1/Loc2/Loc3/
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Load', json={'Location':Location, 'Hash':self._Hash}, verify=True).json())
    
    def delete(self, Location: str):
        '''
        Deletes data at specified location. Raises an exception if location doesn't exist.

        Auth.Delete('Loc1/Loc2/Loc3') Deletes data in Loc1/Loc2/Loc3/
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Delete', json={'Location':Location, 'Hash':self._Hash}, verify=True).json())

    def login(self):
        '''
        Attempts to login with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        self._requestHandle(self._sesh.post(self._Path+ 'Logout', json={'Hash':self._Hash}, verify=True).json())
        return self._requestHandle(self._sesh.post(self._Path+'Login', json={'Username':self._Name, 'Password':self._Pass, 'Hash':self._Hash}, verify=True).json())
        
    def signup(self):
        '''
        Attempts to signup with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Signup', json={'Username':self._Name, 'Password':self._Pass}, verify=True).json())
    
    def remove(self):
        '''
        Attempts to remove the user with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self._requestHandle(self._sesh.post(self._Path+'Remove', json={'Hash':self._Hash}, verify=True).json())
    
    def terminate(self):
        '''
        Closes connection to backend and saves cache
        
        if you do not manually call this, you are at the mercy of the garbage collector (unless you are using the context manager!)
        '''
        if self._active:
            self._requestHandle(self._sesh.post(self._Path+ 'Logout', json={'Hash':self._Hash}, verify=True).json())
            ret = self._requestHandle(self._sesh.post(self._Path+'Leave', json={'Hash':self._Hash}, verify=True).json())
            self._active = False
            return ret
    
    def _requestHandle(self, request, should_kill=True):
        if request['Code'] == 200:
            return self
        
        elif request['Code'] == 202:
            return request['Data']
        
        elif request['Code'] == 416:
            if should_kill:
                self.terminate()
            raise LocationError('Loaction does not exist')
        
        elif request['Code'] == 401:
            if should_kill:
                self.terminate()
            raise PasswordError('Incorrect password')
        
        elif request['Code'] == 404:
            if should_kill:
                self.terminate()
            raise UsernameError('Username does not exist')
        
        elif request['Code'] == 406:
            if should_kill:
                self.terminate()
            raise UsernameError('Invalid username')
        
        elif request['Code'] == 409:
            if should_kill:
                self.terminate()
            raise UsernameError('Username already exists')
        
        elif request['Code'] == 423:
            if should_kill:
                self.terminate()
            raise AuthenticationError('Failed to authenticate user')
        
        elif request['Code'] == 422:
            if should_kill:
                self.terminate()
            raise LocationError(request['err'])

        elif request['Code'] == 101:
            self._Hash = request['Hash']
        
        elif request['Code'] == 102:
            self._certadder(request['Server'])
            
        elif request['Code'] == 204:
            self._removed = True
            
        elif request['Code'] == 420:
            if not self._removed:
                raise SaveError('couldnt find user in database and user was not removed')
            else:
                self._removed = False

class AuthSeshContextManager:
    '''
    Context Manager wrapper for AuthSesh
    '''
    class AuthWrap(AuthSesh):
        
        def __del__(self):
            pass
        
        def _requestHandle(self, request):
            
            return super()._requestHandle(request, should_kill=False)
                
    def __init__(self,  Address: str = None, Path: str = None):
        self.Address = Address
        self.Path = Path
        
    def __enter__(self):
        self.ash = self.AuthWrap(self.Address, self.Path)
        
        return self.ash
    
    def __exit__(self, type, val, trace):
        self.ash.terminate()

def simple_syntax():        
    from maxmods import menu as Menu
    class AuthMenu:
        def MainMenu(self):
            self.Menu = Menu.BasicMenu('Auth Menu')
            self.Menu.add_item(1, 'Login', self.Login, 1)
            self.Menu.add_item(2, 'Signup', self.Login, 2)
            return self.Menu
        def Login(self, val):
            Name = str(input('Username: '))
            Pass = str(input('Password: '))
            self.Auth = AuthSesh().set_vals(Name, Pass)
            try:
                if val == 1:
                    self.Auth.login()
                elif val == 2:
                    self.Auth.signup()
                self.Menu.update_item(1, 'Logout', self.Logout)
                self.Menu.remove_item(2)
                self.Menu.add_item(2, 'Load', self.Load)
                self.Menu.add_item(3, 'Save', self.Save)
                self.Menu.add_item(4, 'Delete', self.Delete)
                self.Menu.Title = f'Welcome {self.Auth.Name}'
            except AuthenticationError as err:
                print(err)
                input('Press enter')
        def Delete(self):
            Loc = str(input('From where: '))
            try:
                self.Auth.delete(Loc)
                input('Press enter')
            except LocationError as err:
                raise err
                input('Press enter')
        def Load(self):
            Loc = str(input('From where: '))
            try:
                print(self.Auth.load(Loc))
                input('Press enter')
            except LocationError as err:
                print(err)
                input('Press enter')
        def Save(self):
            Loc = str(input('To where: '))
            Dat = str(input('What to save: '))
            try:
                self.Auth.save(Loc, Dat)
                input('Press enter')
            except LocationError as err:
                print(err)
                input('Press enter')
        def Logout(self):
            self.Menu.update_item(1, 'Login', self.Login, 1)
            self.Menu.update_item(2, 'Signup', self.Login, 2)
            self.Menu.remove_item(3)
            self.Menu.remove_item(4)
            self.Menu.Title = 'Auth Menu'
            del(self.Auth)
    menu = AuthMenu().MainMenu()
    menu.run()
    
if __name__ == '__main__':
    simple_syntax()