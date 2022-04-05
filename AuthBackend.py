from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with, marshal
from flask_sqlalchemy import SQLAlchemy
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
class DataMod(db.Model):
    Username = db.Column(db.String, nullable=False, primary_key=True)
    Password = db.Column(db.String, nullable=False)
    Data = db.Column(db.JSON)
    def __repr__(self):
        return f"Data(Username = {self.Username}, Password = {self.Password}, Data = {self.Data})"
db.create_all()
Dataargs = reqparse.RequestParser()
Dataargs.add_argument('Username', type=str)
Dataargs.add_argument('Password', type=str)
hand = reqparse.RequestParser()
hand.add_argument('DateTime', type=str)
hand.add_argument('ID', type=str)
Auth1 = reqparse.RequestParser()
Auth1.add_argument('Username', type=str, required=True)
Auth1.add_argument('Password', type=str, required=True)
Auth1.add_argument('ID', type=str, required=True)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}
conns = {}
def Decrypt(Data, ID):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(ID.encode()),
        iterations=390000,
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(conns[ID].encode())))
    fernet = Fernet(key)
    return fernet.decrypt(Data.encode()).decode()
class Data1(Resource):
    @marshal_with(datfields)
    def put(self):
        data = Dataargs.parse_args()
        dat = DataMod.query.get(data['Username']).first()
        return dat
    @marshal_with(datfields)
    def post(self):
        data = Dataargs.parse_args()
        bruh = DataMod(Username=data['Username'], Password=data['Password'], Data={'bruh':'its here'})
        db.session.add(bruh)
        db.session.commit()
        return bruh
class Auth(Resource):
    def put(self):#login
        Args = Auth1.parse_args()
        DEcry = {'Username': Decrypt(Args['Username'], Args['ID']), 'Password': Decrypt(Args['Password'], Args['ID'])}
        dat = DataMod.query.filter_by(Username=DEcry['Username']).first()
        Pass = marshal(dat, passfields)
        if Pass['Password'] == DEcry['Password']:
            return 200
        else:
            return 409
    def post(slef):#signup
        Args = Auth1.parse_args()
        DEcry = {'Username': Decrypt(Args['Username'], Args['ID']), 'Password': Decrypt(Args['Password'], Args['ID'])}
        dat = DataMod.query.filter_by(Username=DEcry['Username']).first()
        if dat:
            abort(409, message='User already exists')
        else:
            inf = DataMod(Username=DEcry['Username'], Password=DEcry['Password'])
            db.session.add(inf)
            db.session.commit()
            return 200
class Shake(Resource):
    def post(self):#greeting
        jointime = hand.parse_args()
        conns[jointime['ID']] = jointime['DateTime']
        return {'DateTime':jointime['DateTime'], 'ID':jointime['ID']}
    def put(self):#goodbyes
        jointime = hand.parse_args()
        del(conns[jointime['ID']])
        return 200
api.add_resource(Auth, '/Auth')
api.add_resource(Shake, '/Shake')
api.add_resource(Data1, '/Data')
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5678, ssl_context=('server-public-key.pem', 'server-private-key.pem'))