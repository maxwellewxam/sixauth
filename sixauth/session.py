from .main import *
from .database import *
from .encryption import *

class Session:
    @logger()
    def __init__(self, path = os.getcwd(), cache_threshold = 300, is_server=False):
        self.cache = Cache(cache_threshold, is_server=is_server)
        self.is_server = is_server
        self.db = Database(path)
        self.function_map = {
            301: self.create_session,
            302: self.sign_up,
            303: self.log_in,
            304: self.log_out,
            305: self.remove_account,
            306: self.save_data,
            307: self.load_data,
            308: self.delete_data,
            309: self.end_session,
            310: self.close_session}
        
    @logger(is_log_more=True, in_sensitive=True)
    def close_session(self,_):
        self.cache.stop_flag.set()
        self.cache.t.join()
        self.db.close()
        return {'code':200}
    
    @logger(in_sensitive=True, out_sensitive=True)
    def __call__(self, **data:dict):
        code = data.get('code')
        if code in self.function_map:
            return self.function_map[code](data)
        else:
            return {'code': 420, 'data':None, 'error': f"Invalid code: {code}"}
    
    @logger(is_log_more=True, in_sensitive=True)
    def create_done_callback(self, hash, id, client):
        @logger(is_log_more=True)
        def callback(_):
            self(code=304, hash=hash, id=id)
            self(code=309, hash=hash, id=id)
            client.kill()
        @logger(is_log_more=True)
        def done_callback(_):
            client.queue.put(callback)
        return done_callback
    
    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def sign_up(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(data['username'])
        if user_from_database:
            return {'code':409}
        encrypted_data, iv = encrypt_data({}, data['password'], data['username'])
        self.db.iv_dict[data['username']] = iv
        self.db.create(data['username'], create_password_hash(data['password']), encrypted_data)
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def save_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if not is_json_serialized(data['data']):
            return {'code':420, 'data':data['data'], 'error':'Object is not json serialized'}
        data_from_request = json.loads(data['data'])
        if data['location'] == '':
            return {'code':417}
        user_from_cache['data'].data.make(data['location'], data_from_request)
        self.cache.update_user(data['hash'], data['id'], user_from_cache['data'])
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def delete_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if data['location'] == '':
            user_from_cache['data'].data.data = {}
        else:
            user_from_cache['data'].data.delete(data['location'])
        self.cache.update_user(data['hash'], data['id'], user_from_cache['data'])
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_out(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':200}
        user_from_database = self.db.find(user_from_cache['data'].username)
        if not user_from_database:
            return {'code':420, 'data':user_from_cache['data'], 'error':'could not find user to logout'}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code': 423}
        encrypted_data, iv = encrypt_data(user_from_cache['data'].data.data, user_from_cache['data'].password, user_from_cache['data'].username)
        self.db.iv_dict[user_from_cache['data'].username] = iv
        self.db.update(user_from_cache['data'].username, encrypted_data)
        self.cache.update_user(data['hash'], data['id'], User())
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def remove_account(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return{'code':423}
        user_from_database = self.db.find(user_from_cache['data'].username)
        if not user_from_database:
            return {'code':423}
        if not verify_password_hash(user_from_database[1], password=user_from_cache['data'].password):
            return {'code':423}
        self.db.delete(user_from_cache['data'].username)
        self.cache.update_user(data['hash'], data['id'], User())
        del self.db.iv_dict[user_from_cache['data'].username]
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def log_in(self, data):
        if data['username'] == '':
            return {'code':406}
        if data['username'].isalnum() == False:
            return {'code':406}
        user_from_database = self.db.find(data['username'])
        if not user_from_database:
            return {'code':404}
        if not verify_password_hash(user_from_database[1], password=data['password']):
            return {'code':401}   
        cache_data = User(decrypt_data(user_from_database[2], data['password'], data['username'], self.db.iv_dict[data['username']]), data['username'], data['password'])
        if self.cache.update_user(data['hash'], data['id'], cache_data)['code'] == 500:
            return {'code':423}
        return {'code':200}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def load_data(self, data):
        user_from_cache = self.cache.find_user(data['hash'], data['id'])
        if user_from_cache['code'] == 500:
            return {'code':423}
        if data['location'] == '':
            return {'code':202, 'data':user_from_cache['data'].data.data}
        val = user_from_cache['data'].data.find(data['location'])
        if val['code'] == 500:
            return {'code':416}
        return {'code':202, 'data':val['data']}

    @logger(is_log_more=True, in_sensitive=True, out_sensitive=True)
    def create_session(self, data):
        user_hash = self.cache.add_user(data['id'])['hash']
        if self.is_server:
            done_call = self.create_done_callback(user_hash, data['id'], data['client'])
            self.cache.add_done_callback(user_hash, data['id'], done_call)
        return {'code':201, 'hash':user_hash}

    @logger(is_log_more=True, in_sensitive=True)
    def end_session(self, data):
        if self.cache.delete_user(data['hash'], data['id'])['code'] == 500:
            return {'code':423}
        return {'code':200}

@logger()
def frontend_session(path = os.getcwd(), cache_threshold = 300):
    session = Session(path, cache_threshold, is_server=True)
    @logger(in_sensitive=True, out_sensitive=True)
    def send_data_to_session(**data:dict):
        code = data.get('code')
        if code in session.function_map:
            return session.function_map[code](data)
        else:
            return {'code': 420, 'data':None, 'error': f"Invalid code: {code}"}
    return send_data_to_session, session