from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import json


def encrypt_data(data, password, salt):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=backend)
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(iv, json.dumps(data).encode(), salt.encode()), iv

def decrypt_data(data, password, salt, iv):
    backend = default_backend()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode(),
        iterations=100000,
        backend=backend)
    key = kdf.derive(password.encode())
    aesgcm = AESGCM(key)
    return json.loads(aesgcm.decrypt(iv, data, salt.encode()).decode())

path = os.getcwd()

if not os.path.exists(path):
    os.makedirs(path)

# define the path to the file where the data will be stored
data_file = f'{path}\\ivs.txt'

# write the encrypted data to the file
def store_data(encrypted_data):
    with open(data_file, 'wb') as f:
        f.write(encrypted_data)

# read the encrypted data from the file
def retrieve_data():
    with open(data_file, 'rb') as f:
        encrypted_data = f.read()
    return json.loads(encrypted_data)

server_ivs = retrieve_data()


data = {'some random text':'weird dict here'}
print(data)
data, iv = encrypt_data(data, 'my password', 'my username')
print(data)
data = decrypt_data(data, 'my password', 'my username', iv)
print(data)

# message to self, we are gonna store the ivs into a file called ivs.txt, we will decrypt the file and laod it in when a new session is made
# we will encrypt it when close session is called. ivs will be a dictionary of usernames -> iv. we will use the fast cryption funcs from main and 
# store this file in the same place as the database, maybe look into finding a way to make a table of username to iv in our current database file
