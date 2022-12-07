from flask import Flask
from flask_restful import Api, Resource, reqparse, fields, marshal
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from datetime import datetime

import os
import jsonpath_ng
import hashlib
import base64
import json
import bcrypt

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.getcwd()}/database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def Encrypt(Data, password, username):
    Data1 = json.dumps(Data)
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
    return json.loads(fernet.decrypt(Data.encode()).decode())

class DataMod(db.Model):
    Username = db.Column(db.String, nullable=False, primary_key = True)
    Password = db.Column(db.String, nullable=False)
    Data = db.Column(db.String)

    def __init__(self, Username, Password, Data):
        self.Username = Username
        self.Password = Password
        self.Data = Data

if os.path.isfile('database.db') is False:
    with app.app_context():
        db.create_all()

Dataargs = reqparse.RequestParser()
Dataargs.add_argument('Location', type=str)
Dataargs.add_argument('Data', type=str)
Dataargs.add_argument('Username', type=str)
Dataargs.add_argument('Password', type=str)
Dataargs.add_argument('Hash', type=str)
Dataargs.add_argument('Id', type=int)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}


def create_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

def check_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))
            
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
        
cache = usercache()
        
class Load(Resource):
    
    def post(self):#load data
        data = Dataargs.parse_args()
        
        userdat = cache.find(data['Hash'])[0]
                        
        if userdat != None:
            try:
                jsonpath_expr = [match.value for match in jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).find(userdat)][0]
                
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

class Save(Resource):

    def post(self):#save data
        data = Dataargs.parse_args()
        userdat = cache.find(data['Hash'])[0]
        userinfo = cache.find(data['Hash'])[1]
        
        if userdat != None:
            try:
                hmm = json.loads(data['Data'])
                jsonpath_ng.parse(num_to_str(data['Location'].replace('/', '.').replace(' ', '-'))).update_or_create(userdat, hmm)
            
            except AttributeError as err:
                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                    try:
                        userdat = json.loads(data['Data'])
                    
                    except Exception as err2:
                        return {'Code':422, 'err':'No location specified or data was not a dict'}
                        
                else:
                    raise AttributeError(err)
            
            cache.update(data['Hash'], [userdat, userinfo])

            return {'Code':200, 'Data':userdat}

        else:
            return {'Code':423}

class Remove(Resource):

    def post(self):#remove user
        data = Dataargs.parse_args()
        username, password = cache.find(data['Hash'])[1]
                        
        with app.app_context():
            fromdat = DataMod.query.filter_by(Username=username).first()
        
        if not fromdat:
            return {'Code':423}

        
        datPass = marshal(fromdat, passfields)['Password']
        
        if check_hash(datPass, password):
            
            with app.app_context():
                db.session.delete(fromdat)
                db.session.commit()
            
            cache.update(data['Hash'], [None,(None,None)])
            
            return {'Code':200}
        
        else:
            return {'Code':423}

class Login(Resource):
    
    def post(self):#login
        data = Dataargs.parse_args()
        if data['Username'] == '':
            return {'Code':406}
        
        if data['Username'].isalnum() == False:
            return {'Code':406}
        
        with app.app_context():
            fromdat = DataMod.query.filter_by(Username=data['Username']).first()
    
        if not fromdat:
            return {'Code':404}
        
        datPass = marshal(fromdat, passfields)['Password']
        
        if check_hash(datPass, data['Password']):
            
            cache.update(data['Hash'], [Decrypt(marshal(fromdat, datfields)['Data'], data['Username'], data['Password']), (data['Password'], data['Username'])]) 
            
            return {'Code':200}
        
        else:
            return {'Code':401}
        
class Signup(Resource):

    def post(slef):#signup
        data = Dataargs.parse_args()
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
                inf = DataMod(Username=data['Username'], Password=create_hash(data['Password']), Data=Encrypt({}, data['Username'], data['Password']))
                db.session.add(inf)
                db.session.commit()
            
            return {'Code':200}

class Greet(Resource):

    def post(self):#greeting
        data = Dataargs.parse_args()
        user = cache.add(data['Id'])
        return {'Code':101, 'Hash':user}

class Leave(Resource):

    def post(self):#goodbyes
        data = Dataargs.parse_args()
        cache.delete(data['Hash'])

        return {'Code':200}

class Delete(Resource):
    
    def post(self):
        data = Dataargs.parse_args()
        userdat = cache.find(data['Hash'])[0]
        userinfo = cache.find(data['Hash'])[1]
        
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
            
            cache.update(data['Hash'], [userdat, userinfo])

            return {'Code':200}

        else:
            return {'Code':423}

class Cert(Resource):
    def post(slef):
        with open('server-public-key.pem') as f:
            serv = f.read()
        return {'Code':102, 'Server': serv}

class Logout(Resource):
    def post(self):
        data = Dataargs.parse_args()
        userdat = cache.find(data['Hash'])[0]
        username, password = cache.find(data['Hash'])[1]

        if userdat is not None:
            with app.app_context():
                fromdat = DataMod.query.filter_by(Username=username).first()
            
            if not fromdat:
                return {'Code':420, 'Data':json.dumps(userdat)}
            
            datPass = marshal(fromdat, passfields)['Password']
            if check_hash(datPass, password):
                
                with app.app_context():
                    db.session.delete(fromdat)
                    db.session.add(DataMod(Username=username, Password=hashlib.sha512((password + username).encode("UTF-8")).hexdigest(), Data=Encrypt(userdat, username, password)))
                    db.session.commit()
                
                return {'Code':200}
            
            else:
                return {'Code':423}

        else:
            return {'Code':200}

class cache1(Resource):
    def get(self):
        return {'Code': 202, 'Data': cache.users}
    def post(self):
        quit()

api.add_resource(Login, '/Login')
api.add_resource(Signup, '/Signup')
api.add_resource(Greet, '/Greet')
api.add_resource(Leave, '/Leave')
api.add_resource(Load, '/Load')
api.add_resource(Save, '/Save')
api.add_resource(Remove, '/Remove')
api.add_resource(Delete, '/Delete')
api.add_resource(Cert, '/Cert')
api.add_resource(Logout, '/Logout')
api.add_resource(cache1, '/cache')

def start_server(host = None, port = None):
    if not os.path.isfile('server-public-key.pem') or not os.path.isfile('server-private-key.pem'):
        from maxmods.auth.auth_backend import __cert_maker__
    app.run(host=host, port=port, ssl_context=('server-public-key.pem', 'server-private-key.pem'))
if __name__ == '__main__':
    start_server('0.0.0.0', 5678)