import sys
import os
# if sys.platform == 'win32':
#     HERE = os.path.abspath('../')
# else:
# HERE = os.path.abspath(os.getcwd())
# sys.path.append(HERE)
# from sixauth.main import backend_session

# hmm = backend_session('127.0.0.1:8888')
# print(hmm(amsdn='234234'))
def setup_logger():
    global logger
    def logger():
        def decorator(func):
            def wrapper(*args, **kwargs):
                print(f'{func.__name__} called with arguments {args} and {kwargs}')
                vals = func(*args, **kwargs)
                print(f'{func.__name__} returned {vals}')
                return vals
            return wrapper
        return decorator
        
setup_logger(True)

@logger()
def foo(bar):
    print(bar)
setup_logger(True)
@logger(True)
def bar(foo, bar):
    foo(bar)
    return foo

foo('yes')

print(bar(foo,'poop'))
    