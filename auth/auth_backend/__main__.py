from flask import Flask
from flask_restful import Api, Resource, reqparse, fields, marshal
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

import os
import jsonpath_ng
import hashlib
import base64
import json

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
Auth1 = reqparse.RequestParser()
Auth1.add_argument('Username', type=str, required=True)
Auth1.add_argument('Password', type=str, required=True)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}

class Load(Resource):
    
    def post(self):#load data
        Args = Auth1.parse_args()
        DataArgs = Dataargs.parse_args()
        if Args['Username'] == '':
            return {'Code':423}
        if Args['Username'].isalnum() == False:
            return {'Code':423}
        fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        if not fromdat:
            return {'Code':423}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            farter = Decrypt(marshal(fromdat, datfields)['Data'], Args['Username'], Args['Password'])
            try:
                jsonpath_expr = [match.value for match in jsonpath_ng.parse(DataArgs['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).find(farter)][0]
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

class Save(Resource):

    def post(self):#save data
        Args = Auth1.parse_args()
        DataArgs = Dataargs.parse_args()
        if Args['Username'] == '':
            return {'Code':423}
        if Args['Username'].isalnum() == False:
            return {'Code':423}
        fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        if not fromdat:
            return {'Code':423}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            new = Decrypt(marshal(fromdat, datfields)['Data'], Args['Username'], Args['Password'])
            try:
                hmm = json.loads(DataArgs['Data'])
                jsonpath_ng.parse(DataArgs['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).update_or_create(new, hmm)
            except TypeError as err:
                return {'Code':422, 'err': str(err)}
            except AttributeError as err:
                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                    try:
                        new = json.loads(DataArgs['Data'])
                    except Exception as err2:
                        return {'Code':422, 'err': str(err2)}
                else:
                    raise AttributeError(err)
            except Exception as err:
                return {'Code':422, 'err': str(err)}
            db.session.delete(fromdat)
            db.session.add(DataMod(Username=Args['Username'], Password=hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt(new, Args['Username'], Args['Password'])))
            db.session.commit()
            return {'Code':200}
        else:
            return {'Code':423}

class Remove(Resource):

    def post(self):#remove user
        Args = Auth1.parse_args()
        if Args['Username'] == '':
            return {'Code':423}
        if Args['Username'].isalnum() == False:
            return {'Code':423}
        fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        if not fromdat:
            return {'Code':423}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            db.session.delete(fromdat)
            
            db.session.commit()
            return {'Code':200}
        else:
            return {'Code':423}

class Login(Resource):
    
    def post(self):#login
        Args = Auth1.parse_args()
        if Args['Username'] == '':
            return {'Code':406}
        if Args['Username'].isalnum() == False:
            return {'Code':406}
        fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        if not fromdat:
            return {'Code':404}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            return {'Code':200}
        else:
            return {'Code':401}
        
class Signup(Resource):

    def post(slef):#signup
        Args = Auth1.parse_args()
        if Args['Username'] == '':
            return {'Code':406}
        if Args['Username'].isalnum() == False:
            return {'Code':406}
        fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        if fromdat:
            return {'Code':409}
        else:
            inf = DataMod(Username=Args['Username'], Password=hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt({}, Args['Username'], Args['Password']))
            db.session.add(inf)
            db.session.commit()
            return {'Code':200}

class Greet(Resource):

    def post(self):#greeting
        with open('server-public-key.pem') as f:
            serv = f.read()
        return {'Code':101, 'Server': serv}

class Leave(Resource):

    def post(self):#goodbyes
        return {'Code':200}

class Delete(Resource):
    
    def post(self):
        Args = Auth1.parse_args()
        DataArgs = Dataargs.parse_args()
        if Args['Username'] == '':
            return {'Code':423}

        if Args['Username'].isalnum() == False:
            return {'Code':423}
        
        with app.app_context():
            fromdat = DataMod.query.filter_by(Username=Args['Username']).first()
        
        if not fromdat:
            return {'Code':423}
        
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest()
        
        if userPass == datPass:
            new = Decrypt(marshal(fromdat, datfields)['Data'], Args['Username'], Args['Password'])
            try:
                yes = jsonpath_ng.parse(DataArgs['Location'].replace('/', '.').replace(' ', '-').replace('1', 'one').replace('2', 'two').replace('3', 'three').replace('4', 'four').replace('5', 'five').replace('6', 'six').replace('7', 'seven').replace('8', 'eight').replace('9', 'nine').replace('0', 'zero')).find(new)
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
                db.session.add(DataMod(Username=Args['Username'], Password=hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt(new, Args['Username'], Args['Password'])))
                db.session.commit()
            return {'Code':200}

        else:
            return {'Code':423}

api.add_resource(Login, '/Login')
api.add_resource(Signup, '/Signup')
api.add_resource(Greet, '/Greet')
api.add_resource(Leave, '/Leave')
api.add_resource(Load, '/Load')
api.add_resource(Save, '/Save')
api.add_resource(Remove, '/Remove')
api.add_resource(Delete, '/Delete')


def start_server(host = None, port = None):
    if not os.path.isfile('server-public-key.pem') or not os.path.isfile('server-private-key.pem'):
        from maxmods.auth.auth_backend import __cert_maker__
    app.run(host=host, port=port, ssl_context=('server-public-key.pem', 'server-private-key.pem'))
if __name__ == '__main__':
    start_server('0.0.0.0', 5678)
print('closed')