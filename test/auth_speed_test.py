from maxmods.primitives.randomfuncs import Timer
from maxmods.auth import AuthSesh as ash
from maxmods.auth import AuthSeshContextManager as ascm

server = ash('https://localhost:5678/').set_vals('max', 'max')
# t = Timer()

# t.run_time(server.login)
# print(t.message)

server.login()
#server.kill()

# with ascm('https://localhost:5678/') as server:
#     server.set_vals('max', 'max')
#     server.signup()