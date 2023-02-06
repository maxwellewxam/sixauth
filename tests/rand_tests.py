import sys
import os
# # if sys.platform == 'win32':
# #     HERE = os.path.abspath('../')
# # else:
# HERE = os.path.abspath(os.getcwd())
# sys.path.append(HERE)
# from sixauth.main import backend_session

# hmm = backend_session('127.0.0.1:5678')
# hmm1 = backend_session('127.0.0.1:5678')
# hmm2 = backend_session('127.0.0.1:5678')
# hmm3 = backend_session('127.0.0.1:5678')
# print(hmm(amsdn='234234'))
# print(hmm1(amsdn='234234'))
# print(hmm2(amsdn='234234'))
# print(hmm3(amsdn='234234'))

from

logger = Logger()

@logger(is_log_more=True)
def foo_bar(arg):
    print(arg)

logger.__init__(log_more=True)
foo_bar('some text')