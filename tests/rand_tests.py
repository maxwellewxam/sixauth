import classes
from cryptography.fernet import Fernet

cache = classes.Cache(60)

id = Fernet.generate_key().hex()

hash = cache.add_user(id)['hash']

cache.update_user(hash, id, {}, 'max', 'password')

user = cache.find_user(hash, id)['data'].retrive(id)

print(user.username)

print(cache.cache[hash]['main'].username)

cache.stop_flag.set()

cache.t.join()