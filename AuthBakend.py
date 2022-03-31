from flask import Flask
from flask_restful import Api, Resource
app = Flask(__name__)
api = Api(app)
class Main(Resource):
    def get(self, name):
        return {'data': str(name) + ' ayo?'}
class HandShake(Resource):
    def get(self, jointime):
        return {'Data':[{'Time':jointime, 'ID':hash(repr(app)+repr(api))}]}
api.add_resource(Main, '/Main/<string:name>')
api.add_resource(HandShake, '/<string:jointime>')
if __name__ == '__main__':
	app.run(debug=True, host='0.0.0.0', port=5678)