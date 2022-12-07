# from maxmods.primitives.randomfuncs import Timer
# from maxmods.auth import AuthSesh as ash
import bcrypt

def create_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_hash(hash, password):
    return bcrypt.checkpw(password.encode('utf-8'), hash)

asd = create_hash('password')

print(check_hash(asd, 'password'))