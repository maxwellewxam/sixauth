from maxmods.primitives.randomfuncs import Timer
from maxmods.auth import AuthSesh as ash
from maxmods.auth import AuthSeshContextManager as ascm
from maxmods.imports.authimports import *

t = Timer()
def main():
    with ascm('https://127.0.0.1:5678/') as server:
        server.set_vals('max', 'max')
        server.login()
        server.save('sdfsfg/sdfg/dfgdfg/dfgdsdgjdguomfbxgh/cgyicxvsZEF', {'URMOM':'test'})
        print(server.load())
        server.delete('sdfsfg/sdfg/dfgdfg/dfgdsdgjdguomfbxgh')
        print(server.load())
        server.remove()
        server.set_vals('max1', 'max1')
        server.login()
        server.save('sdfsfg/sdfg/dfgdfg/dfgdsdgjdguomfbxgh/cgyicxvsZEF', {'URMOM':'test'})
        print(server.load())
        server.delete('sdfsfg/sdfg/dfgdfg/dfgdsdgjdguomfbxgh')
        print(server.load())
        server.set_vals('max', 'max')
        server.signup()
        server.login()
        print(server.load())
        server.set_vals('max1', 'max1')
        server.login()
        print(server.load())
        
t.run_time(main)
print(t.message)        

# with ascm('https://127.0.0.1:5678/') as f:
#     f.set_vals('max1', 'max1')
#     f.signup()
#     f.login()
