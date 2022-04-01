
import requests
import hashlib
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
Base = 'http://127.0.0.1:5678/'
conns={}
def Encrypt(Data, ID):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes(ID.encode()),
        iterations=390000,
        )
    key = base64.urlsafe_b64encode(kdf.derive(bytes(conns[ID].encode())))
    fernet = Fernet(key)
    return fernet.encrypt(Data.encode()).decode()
print(requests.post(Base+'Shake', {'DateTime': '1230', 'ID':'bruh'}).json())
# print(requests.post(Base+'Data', {'Username':'Max', 'Password':'3008362'}).json())
conns['bruh'] = '1230'
name = Encrypt('max', 'bruh')
Pass = Encrypt('3008362', 'bruh')
print(requests.put(Base+'Auth', {'Username':name, 'Password':Pass, 'ID': 'bruh'}).json())
print(requests.put(Base+'Shake', {'ID':'bruh'}).json())