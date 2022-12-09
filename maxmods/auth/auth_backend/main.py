from flask_restful import Api, Resource, reqparse, fields
from maxmods.auth.imports import *


func = authClass()
session = func.Session()
api = Api(func.app)


Dataargs = reqparse.RequestParser()
Dataargs.add_argument('Location', type=str)
Dataargs.add_argument('Data', type=str)
Dataargs.add_argument('Username', type=str)
Dataargs.add_argument('Password', type=str)
Dataargs.add_argument('Hash', type=str)
Dataargs.add_argument('Id', type=int)
datfields = {'Data': fields.Raw}
passfields = {'Password': fields.String}


        
class Load(Resource):
    
    def post(self):#load data
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Location':data['Location'], 'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()

class Save(Resource):

    def post(self):#save data
        data = Dataargs.parse_args()

        return session.post('Load', None, {'Location':data['Location'], 'Data':data['Data'], 'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()

class Remove(Resource):

    def post(self):#remove user
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()

class Login(Resource):
    
    def post(self):#login
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Username':data['Username'], 'Password':data['Password'], 'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()
        
class Signup(Resource):

    def post(slef):#signup
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Username':data['Username'], 'Password':data['Password']}, verify=True).json()

class Greet(Resource):

    def post(self):#greeting
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Id':data['Id']}, verify=True).json()

class Leave(Resource):

    def post(self):#goodbyes
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()

class Delete(Resource):
    
    def post(self):
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Location':data['Location'], 'Hash':data['hash'], 'Id':data['ID']}, verify=True).json()

class Cert(Resource):
    def post(slef):
        with open('server-public-key.pem') as f:
            serv = f.read()
        return {'Code':102, 'Server': serv}

class Logout(Resource):
    def post(self):
        data = Dataargs.parse_args()
        
        return session.post('Load', None, {'Hash':data['hash'], 'Id':data['Id']}, verify=True).json()

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

def start_server(host = None, port = None):
    if not os.path.isfile('server-public-key.pem') or not os.path.isfile('server-private-key.pem'):
        from maxmods.auth.auth_backend import cert_maker
    func.app.run(host=host, port=port, ssl_context=('server-public-key.pem', 'server-private-key.pem'))
if __name__ == '__main__':
    start_server('0.0.0.0', 5678)