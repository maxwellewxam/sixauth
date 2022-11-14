'''An all-in-one user authenticator and data manager'''

from maxmods.imports.authimports import *

class LocationError(BaseException): ...
class AuthenticationError(BaseException): ...
class UsernameError(AuthenticationError): ...
class PasswordError(AuthenticationError): ...

class AuthSesh:
    '''
    Main class of the Auth module
    
    AuthSesh() connects to database internally
    
    AuthSesh(Address) connects to backend Auth server at address in path

    AuthSesh(Path) connects to database internally to database at Path location

    repr(AuthSesh) returns the current username
    '''
    
    def __init__(self, Address: str = None, Path: str = None, HandshakeData = None):
        self.__Path = Path
        self.__Address = Address
        if self.__Address == None:
            
            app = Flask(__name__)
            if self.__Path == None:
                app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
            else:
                app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{self.__Path}/database.db'
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
            
            if self.__Path == None:        
                if os.path.isfile(f'{os.getcwd()}/database.db') is False:
                    with app.app_context():
                        db.create_all()

            else:
                if os.path.isfile(f'{self.__Path}/database.db') is False:
                    with app.app_context():
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
                        if data['Username'] == '':
                            return {'Code':423}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        if userPass == datPass:
                            new = Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password'])
                            try:
                                hmm = jjson.loads(data['Data'])
                                jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).update_or_create(new, hmm)
                            except:
                                try:
                                    jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).update_or_create(new, data['Data'])
                                    
                                except TypeError as err:
                                    raise TypeError(err)
                                
                                except AttributeError as err:
                                    if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                                        try:
                                            new = jjson.loads(data['Data'])
                                        except Exception as err2:
                                            return {'Code':422, 'err':'No location specified or data was not a dict'}

                                    else:
                                        raise AttributeError(err)
                            with app.app_context():
                                db.session.delete(fromdat)
                                db.session.add(DataMod(Username=data['Username'], Password=hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt(new, data['Username'], data['Password'])))
                                db.session.commit()
                            return {'Code':200}

                        else:
                            return {'Code':423}

                    elif location == 'Delete':
                        if data['Username'] == '':
                            return {'Code':423}
                        
                        if data['Username'].isalnum() == False:
                            return {'Code':423}
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        
                        if userPass == datPass:
                            new = Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password'])
                            try:
                                yes = jsonpath_ng.parse(data['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).find(new)
                                del [match.context for match in yes][0].value[str([match.path for match in yes][0])]
                            except TypeError as err:
                                    raise TypeError(err)

                            except AttributeError as err:
                                    raise AttributeError(err)
                            except IndexError as err:
                                if str(err) == 'list index out of range':
                                    return {'Code':416}
                            
                            with app.app_context():
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
                        
                        with app.app_context():
                            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
                        
                        if not fromdat:
                            return {'Code':423}
                        
                        datPass = marshal(fromdat, passfields)['Password']
                        userPass = hashlib.sha512((data['Password'] + data['Username']).encode("UTF-8")).hexdigest()
                        
                        if userPass == datPass:
                            with app.app_context():
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
                        
                        with app.app_context():
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
                        
                        with app.app_context():
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
            self.__Path = ''
        else:
            self.__sesh = requests.Session()
            self.__Path = self.__Address
        try:
            warnings.filterwarnings('ignore')
            self.__requestHandle(self.__sesh.post(self.__Path + 'Greet', HandshakeData, verify=False).json())
            
        except requests.ConnectionError as err:
            raise LocationError('Couldn\'t connect to backend server\nMessage:\n' + str(err))

    def __repr__(self):
        return f'AuthSesh({self.__Path}).set_vals({self.__Name}, {self.__Pass})'
    
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
    
    def set_vals(self, Name: str, Pass:str):
        '''
        Sets the desired username and password 
        '''
        self.__Name = Name
        self.__Pass = Pass
        return self
    
    def save(self, Location: str, Data):
        '''
        Saves data to the specified location. Creates location if it doesn't exist

        If no location is specified and the data is a Dict, it will replace everythin with the Dict

        rasies LocationError if it fails

        Auth.Save('Loc1/Loc2/Loc3', 'Data') 
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Save', json={'Username':self.__Name, 'Password':self.__Pass, 'Location':Location, 'Data':Data}, verify=True).json())
    def load(self, Location: str):
        '''
        Loads data at specified location. Raises an exception if location doesn't exist

        Auth.Load('Loc1/Loc2/Loc3') Returns data in Loc1/Loc2/Loc3/
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Load', json={'Username':self.__Name, 'Password':self.__Pass, 'Location':Location}, verify=True).json())
    
    def delete(self, Location: str):
        '''
        Deletes data at specified location. Raises an exception if location doesn't exist.

        Auth.Delete('Loc1/Loc2/Loc3') Deletes data in Loc1/Loc2/Loc3/
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Delete', json={'Username':self.__Name, 'Password':self.__Pass, 'Location':Location}, verify=True).json())

    def login(self):
        '''
        Attempts to login with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Login', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
        
    def signup(self):
        '''
        Attempts to signup with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Signup', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
    
    def remove_User(self):
        '''
        Attempts to remove the user with specified Auth.Name and Auth.Pass values
        
        Raises an exception if it fails
        '''
        return self.__requestHandle(self.__sesh.post(self.__Path+'Remove', json={'Username':self.__Name, 'Password':self.__Pass}, verify=True).json())
    
    def __requestHandle(self, request):
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
        
        elif request['Code'] == 422:
            raise LocationError(request['err'])

        elif request['Code'] == 101:
            self.__cert_adder(request['Server'])

def simple_syntax():        
    from MaxMods import menu as Menu
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
                    self.Auth.Login()
                elif val == 2:
                    self.Auth.Signup()
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