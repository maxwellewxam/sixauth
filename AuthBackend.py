from flask import Flask
from flask_restful import Api, Resource, reqparse, abort, fields, marshal
from flask_sqlalchemy import SQLAlchemy
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import os
app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
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
Dataargs.add_argument('Value', type=str)
Auth1 = reqparse.RequestParser()
Auth1.add_argument('Username', type=str, required=True)
Auth1.add_argument('Password', type=str, required=True)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}
class Data1(Resource):
    def put(self):#load data
        Args = Auth1.parse_args()
        DataArgs = Dataargs.parse_args()
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return {'Code':423}
        if fromuser['Username'].isalnum() == False:
            return {'Code':423}
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if not fromdat:
            return {'Code':423}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            farter = dict(marshal(fromdat, datfields)['Data'])
            temp = farter['Data'][0]
            print(temp)
            locate = list(DataArgs['Location'].split("/"))
            locate.insert(0, 'yup')
            print(locate)
            for i in range(len(locate)):
                try:
                    newtemp = temp[locate[i]]
                except:
                    return {'Code':416}
                temp = newtemp[0]
            return {'Data':newtemp, 'Code':202}
        else:
            return {'Code':423}
    def post(self):#save data
        Args = Auth1.parse_args()
        DataArgs = Dataargs.parse_args()
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return {'Code':423}
        if fromuser['Username'].isalnum() == False:
            return {'Code':423}
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if not fromdat:
            return {'Code':423}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            farter = dict(marshal(fromdat, datfields)['Data'])
            temp = farter['Data'][0]
            locate = list(DataArgs['Location'].split("/"))
            DData = [{DataArgs['Value']:DataArgs['Data']}]
            print(DData)
            locate.insert(0, 'yup')
            print(len(locate))
            for i in range(len(locate)):
                try:
                    if i == len(locate)-1:
                        temp[locate[i]] = DData
                    else:
                        newtemp = temp[locate[i]]
                except:
                    if i == len(locate)-1:
                        temp[locate[i]] = DData
                    else:
                        temp[locate[i]] = [{}]
                        newtemp = temp[locate[i]]
                temp = newtemp[0]
            db.session.delete(fromdat)
            db.session.commit()
            inf = DataMod(Username=fromuser['Username'], Password=hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest(), Data=farter)
            db.session.add(inf)
            db.session.commit()
            print(farter)
            return {'Code':200}
        else:
            return {'Code':423}
class Auth(Resource):
    def put(self):#login
        Args = Auth1.parse_args()
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return {'Code':406}
        if fromuser['Username'].isalnum() == False:
            return {'Code':406}
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if not fromdat:
            return {'Code':404}
        datPass = marshal(fromdat, passfields)['Password']
        userPass = hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest()
        if userPass == datPass:
            return {'Code':200}
        else:
            return {'Code':401}
    def post(slef):#signup
        Args = Auth1.parse_args()
        fromuser = {'Username': Args['Username'], 'Password': Args['Password']}
        if fromuser['Username'] == '':
            return {'Code':406}
        if fromuser['Username'].isalnum() == False:
            return {'Code':406}
        fromdat = DataMod.query.filter_by(Username=fromuser['Username']).first()
        if fromdat:
            return {'Code':409}
        else:
            inf = DataMod(Username=fromuser['Username'], Password=hashlib.sha512((fromuser['Password'] + fromuser['Username']).encode("UTF-8")).hexdigest(), Data={'Data':[{}]})
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
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5678, ssl_context=('server-public-key.pem', 'server-private-key.pem'))
print('closed')