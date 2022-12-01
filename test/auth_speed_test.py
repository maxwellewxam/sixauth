from maxmods.primitives.randomfuncs import Timer
from maxmods.auth import AuthSesh as ash
from maxmods.auth import AuthSeshContextManager as ascm
from maxmods.imports.authimports import *

t = Timer()
# server = t.run_time(ash)#, 'https://127.0.0.1:5678/')
# print(t.message)
# server.set_vals('max', 'max')

# t.run_time(server.signup)
# print(t.message)

# t.run_time(server.login)
# print(t.message)

# #t.run_time(server.delete, 'sdf/sdf')
# #print(t.message)

# print(t.run_time(server.load))
# print(t.message)

# t.run_time(server.remove)
# print(t.message)

# print(t.run_time(server.terminate))
# print(t.message)
def main():
    with ascm() as server:
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