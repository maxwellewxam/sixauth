import sys
import os
import time
import threading
import random
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import AuthSesh

with AuthSesh('127.0.0.1:5678') as ash:
    ash.set_vals('max', 'max')
    ash.signup()


def foobar(count,hmmm):
    ash = AuthSesh('127.0.0.1:5678')
    ash.set_vals(f'max{count}', 'max')
    ash.signup()
    ash.login()
    ash.save('',f'sensitive data{count}')
    print(ash.load())
    ash.set_vals('max', 'max')
    ash.login()
    ash.save(f'lol/{count}/die{hmmm}',f'sensitive data{count}')
    ash.set_vals(f'max{count}', 'max')
    ash.login()
    print(ash.load())
    ash.remove()
    ash.terminate()

threads=[]

for i in range(500):
    client_thread = threading.Thread(target=foobar, args=(i,random.random()))
    client_thread.start()
    threads.append(client_thread)
for thread in threads:
    thread.join()