from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import os

app = Flask(__name__)
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
db.session.add(DataMod(Username='Maxs', Password='lol', Data={'more':'lol'}))
db.session.commit()
fromdat = DataMod.query.filter_by(Username='Max').first()
print(fromdat)