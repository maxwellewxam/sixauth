from classes import Cache, User
from cryptography.fernet import Fernet

cache = Cache(60)

id = Fernet.generate_key().hex()

hash = cache.add_user(id)['hash']

cache.update_user(hash, id, User({}, 'max', 'password'))

user = cache.find_user(hash, id)['data']

print(user.username)

print(cache.cache[hash]['main'])

cache.stop_flag.set()

cache.t.join()