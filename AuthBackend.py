from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with, marshal
from flask_sqlalchemy import SQLAlchemy
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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
hand.add_argument('JoinTime', type=str)
hand.add_argument('ID', type=str)
Auth1 = reqparse.RequestParser()
Auth1.add_argument('Username', type=str, required=True)
Auth1.add_argument('Password', type=str, required=True)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}
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
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return 400
        if fromuser['Username'].isalnum() == False:
            return 406
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if not fromdat:
            return 404
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            return 200
        else:
            return 401
    def post(slef):#signup
        Args = Auth1.parse_args()
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return 400
        if fromuser['Username'].isalnum() == False:
            return 406
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if fromdat:
            return 409
        else:
            inf = DataMod(Username=fromuser['Username'], Password=fromuser['Password'])
            db.session.add(inf)
            db.session.commit()
            return 200
class Shake(Resource):
    def post(self):#greeting
        jointime = hand.parse_args()
        return {'JoinTime':str(datetime.now())}
    def put(self):#goodbyes
        jointime = hand.parse_args()
        return 200
api.add_resource(Auth, '/Auth')
api.add_resource(Shake, '/Shake')
api.add_resource(Data1, '/Data')
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5679, ssl_context=('server-public-key.pem', 'server-private-key.pem'))
print('closed')