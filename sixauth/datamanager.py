from .main import *
from .encryption import *

class Data:
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, data):
        self.data = data
    
    @logger(is_log_more=True, out_sensitive=True)
    def store(self):
        return self.data
    
    @logger(is_log_more=True, in_sensitive=True)
    def make(self, path:str, data):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if not len([match for match in temp.keys() if match == name]) > 0:
                temp[name] = {'data': None, 'folder':{}}
            if len(path)==pos+1:
                temp[name]['data'] = data
                return {'code':200}
            temp = temp[name]['folder']

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find(self, path:str):
        path = path.split('/')
        temp = self.data
        try:
            for pos, name in enumerate(path):
                if len(path)==pos+1:
                    return {'code':200, 'data':temp[name]['data']}
                temp = temp[name]['folder']
        except KeyError:
            return {'code': 500}

    @logger(is_log_more=True, in_sensitive=True)
    def delete(self, path:str):
        path = path.split('/')
        temp = self.data
        for pos, name in enumerate(path):
            if len(path)==pos+1:
                del temp[name]
                return {'code':200}
            temp = temp[name]['folder']

class User:
    data: Data
    @logger(is_log_more=True, in_sensitive=True)
    def __init__(self, data = None, username = None, password = None, done_callback = None):
        self.data = Data(data)
        self.username = username
        self.password = password
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def store(self, id):
        self.data = self.data.store()
        return encrypt_data_fast(self.__dict__, id)
    
    @logger(is_log_more=True, in_sensitive=True)
    def from_dict(self, dict, id):
        self.__dict__ = decrypt_data_fast(dict, id)
        self.data = Data(self.data)
        return self

class Cache:
    @logger(is_log_more=True)
    def __init__(self, threshold = 300, is_server=False):
        self.cache = {}
        self.threshold = threshold
        self.stop_flag = threading.Event()
        if is_server:    
            self.t = threading.Thread(target=self.cache_timeout_thread)
            self.t.start()

    def default_done_callback(self, hash):
        def done_callback():
            del self.cache[hash]
        return done_callback
    
    @logger(is_log_more=True)
    def cache_timeout_thread(self):
        while not self.stop_flag.is_set():
            try:
                for key in list(self.cache):
                    if time.time() - self.cache[key]['time'] > self.threshold:
                        self.cache[key]['done']()
                time.sleep(1)
            except Exception as err:
                server_console.info(err)
    
    def add_done_callback(self, hash, id, callback):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['done'] = callback
        return {'code':200}
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def add_user(self, id):
        hash = hashlib.sha512((f'{id}{datetime.now()}').encode("UTF-8")).hexdigest()
        self.cache[hash] = {'main':User().store(id), 'time':time.time(), 'done':self.default_done_callback(hash)}
        return {'code':200, 'hash':hash}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['time'] = time.time()
        data = User().from_dict(self.cache[hash]['main'], id)
        if data.username == None:
            return {'code':500}
        return {'code':200, 'data':data}
    
    @logger(is_log_more=True, in_sensitive=True)
    def update_user(self, hash, id, user):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        self.cache[hash]['main'] = user.store(id)
        self.cache[hash]['time'] = time.time()
        return {'code':200}
        
    @logger(is_log_more=True, in_sensitive=True)
    def delete_user(self, hash, id):
        if not is_valid_key(self.cache[hash]['main'], id):
            return {'code':500}
        del self.cache[hash]
        return {'code':200}

class Database:
    @logger(is_log_more=True)
    def __init__(self, path):
        db_path = f'sqlite:///{path}/database.db'
        client_logger.info(f'Database located at: {db_path}')
        engine = create_engine(db_path, connect_args={'check_same_thread':False}, poolclass=StaticPool)
        metadata = MetaData()
        self.users = Table('users', metadata,
            Column('username', String, unique=True, primary_key=True),
            Column('password', String),
            Column('data', LargeBinary))
        self.ivs = Table('ivs', metadata,
            Column('server', String, unique=True, primary_key=True),
            Column('iv', LargeBinary), 
            Column('bytes', LargeBinary))
        metadata.create_all(engine)
        self.conn = engine.connect()
        self.iv = 'server_iv'
        from_database = self.conn.execute(self.ivs.select().where(self.ivs.c.server == self.iv)).fetchone()
        if from_database:
            _,ivs_bytes,bites = from_database
            self.key, self.salt = separate(bites)
            self.iv_dict = server_decrypt_data(ivs_bytes, self.key, self.salt)
        else:
            self.iv_dict = {}
            self.key = b'CHANGE'
            self.salt = b'THIS'
            bites = self.key+b'\x99'+self.salt
            self.conn.execute(self.ivs.insert().values(server=self.iv, iv=server_encrypt_data(self.iv_dict, self.key, self.salt), bytes=bites))
    
    def change_keys(self, key, salt):
        self.key = key
        self.salt = salt
    
    @logger(is_log_more=True)
    def close(self):
        self.conn.execute(self.ivs.update().where(self.ivs.c.server == self.iv).values(iv=server_encrypt_data(self.iv_dict, self.key, self.salt)))
        self.conn.commit()
        self.conn.close()
        
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def create(self, username, password, data):
        self.conn.execute(self.users.insert().values(username=username, password=password, data=data))
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def find(self, username):
        return self.conn.execute(self.users.select().where(self.users.c.username == username)).fetchone()
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def update(self, username, data):
        return self.conn.execute(self.users.update().where(self.users.c.username == username).values(data=data))
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def delete(self, username):
        return self.conn.execute(self.users.delete().where(self.users.c.username == username))

__all__ = ['Data', 'User', 'Cache', 'Database']