import sys
import os
# if sys.platform == 'win32':
#     HERE = os.path.abspath('../')
# else:
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from sixauth.logs.log_class import Logger
from sixauth.main import server_console, client_console, server_logger, client_logger, console_handler, formatter
# hmm = backend_session('127.0.0.1:5678')
# hmm1 = backend_session('127.0.0.1:5678')
# hmm2 = backend_session('127.0.0.1:5678')
# hmm3 = backend_session('127.0.0.1:5678')
# print(hmm(amsdn='234234'))
# print(hmm1(amsdn='234234'))
# print(hmm2(amsdn='234234'))
# print(hmm3(amsdn='234234'))


logger = Logger(server_console, client_console, server_logger, client_logger, console_handler, formatter).setup_logger(debug=True)

@logger(is_log_more=True)
def foo_bar(arg):
    print(arg)
foo_bar('some text')
logger.setup_logger(log_more=True,debug=True)
foo_bar('some text')