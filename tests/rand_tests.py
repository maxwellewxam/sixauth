import sys
import os
import time
import threading
import random
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import AuthSesh

with AuthSesh('127.0.0.1:5678') as ash:
    ash.set_vals('lauren', 'supersecretpassword')
    #ash.signup()



def foobar(count,hmmm):
        with AuthSesh('127.0.0.1:5678') as user2:
            user2.set_vals(f'test{count}', 'test')
            user2.signup()
            user2.login()
            user2.login()
            user2.login()
            user2.login()
            user2.login()
            user2.login()
            user2.remove()

threads=[]

for i in range(1000):
    client_thread = threading.Thread(target=foobar, args=(i,random.random()))
    client_thread.start()
    time.sleep(0.1)
    threads.append(client_thread)
for thread in threads:
    thread.join()