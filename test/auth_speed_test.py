from maxmods.imports.randomfuncs import Timer
from maxmods.auth import AuthSesh as ash

server = ash('https://localhost:5678/').set_vals('max', 'max')
server.signup()