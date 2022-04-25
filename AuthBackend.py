from flask import Flask
from flask_restful import Api, Resource, reqparse, fields, marshal
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime
import os
import jsonpath_ng
import hashlib
import base64
import json

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

def Encrypt(Data, password, username):
    Data1 = json.dumps(Data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(username.encode()),
        iterations=390000,
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
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(password.encode())))
    fernet = Fernet(key)
    return json.loads(fernet.decrypt(Data.encode()).decode())

class DataMod(db.Model):
    Username = db.Column(db.String, nullable=False, primary_key = True)
    Password = db.Column(db.String, nullable=False)
    Data = db.Column(db.JSON)

    def __init__(self, Username, Password, Data):
        self.Username = Username
        self.Password = Password
        self.Data = Data

if os.path.isfile('database.db') is False:
    db.create_all()

Dataargs = reqparse.RequestParser()
Dataargs.add_argument('Location', type=str)
Dataargs.add_argument('Data', type=str)
Auth1 = reqparse.RequestParser()
Auth1.add_argument('Username', type=str, required=True)
Auth1.add_argument('Password', type=str, required=True)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}

class Data1(Resource):

    def put(self):#load data
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
                jsonpath_expr = [match.value for match in jsonpath_ng.parse(DataArgs['Location'].replace('/', '.').replace(' ', '-')).find(farter)][0]
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
                jsonpath_ng.parse(DataArgs['Location'].replace('/', '.').replace(' ', '-')).update_or_create(new, DataArgs['Data'])
            except TypeError as err:
                if err == '\'str\' object does not support item assignment':
                    return {'Code':422}
            except AttributeError as err:
                if str(err) == '\'NoneType\' object has no attribute \'lineno\'':
                    try:
                        new = json.loads(DataArgs['Data'])
                    except:
                        return {'Code':422}
                else:
                    raise AttributeError(err)
            db.session.delete(fromdat)
            db.session.add(DataMod(Username=Args['Username'], Password=hashlib.sha512((Args['Password'] + Args['Username']).encode("UTF-8")).hexdigest(), Data=Encrypt(new, Args['Username'], Args['Password'])))
            db.session.commit()
            return {'Code':200}
        else:
            return {'Code':423}

class User(Resource):

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

class Auth(Resource):

    def put(self):#login
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

class Shake(Resource):

    def post(self):#greeting
        return {'Code':200, 'JoinTime':str(datetime.now())}

    def put(self):#goodbyes
        return {'Code':200}

api.add_resource(Auth, '/Auth')
api.add_resource(Shake, '/Shake')
api.add_resource(Data1, '/Data')
api.add_resource(User, '/User')

if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5678, ssl_context=('server-public-key.pem', 'server-private-key.pem'))

print('closed')