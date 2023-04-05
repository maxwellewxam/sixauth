from .main import *

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_encrypt_data(data:dict, key:str, salt:bytes):
    for k, v in data.items():
        data[k] = base64.b64encode(v).decode()
    json_data = json.dumps(data)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(key.encode())))
    fernet = Fernet(key)
    return fernet.encrypt(json_data.encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def server_decrypt_data(data:bytes, key:str, salt:bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend())
    key = base64.urlsafe_b64encode(kdf.derive(bytes(key.encode())))
    fernet = Fernet(key)
    iv_dict = json.loads(fernet.decrypt(data))
    for k, v in iv_dict.items():
        iv_dict[k] = base64.b64decode(v.encode())
    return iv_dict
        
@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data(data:dict, password:str, salt:str):
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

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data(data:bytes, password:str, salt:str, iv:bytes):
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

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def encrypt_data_fast(message:dict, key:str):
    return Fernet(bytes.fromhex(key)).encrypt(json.dumps(message).encode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def decrypt_data_fast(message:bytes, key:str):
    return json.loads(Fernet(bytes.fromhex(key)).decrypt(message).decode())

@logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
def create_password_hash(password:str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).hex()

@logger(is_log_more=True, in_sensitive=True)
def verify_password_hash(hash:str, password:str):
    return bcrypt.checkpw(password.encode('utf-8'), bytes.fromhex(hash))

@logger(is_log_more=True, in_sensitive=True)
def is_json_serialized(obj:dict):
    try:
        json.loads(obj)
        return True
    except json.decoder.JSONDecodeError:
        return False

@logger(is_log_more=True, in_sensitive=True)
def is_valid_key(data:bytes, id:str):
    try:
        decrypt_data_fast(data, id)
        return True
    except InvalidToken:
        return False

__all__ = ['server_encrypt_data',
           'server_decrypt_data',
           'encrypt_data',
           'decrypt_data',
           'encrypt_data_fast',
           'decrypt_data_fast',
           'create_password_hash',
           'verify_password_hash',
           'is_json_serialized',
           'is_valid_key']