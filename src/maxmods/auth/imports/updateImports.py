import subprocess
import sys
def install(name):
    subprocess.run([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
    subprocess.run([sys.executable, '-m', 'pip', 'uninstall', name])
    subprocess.run([sys.executable, '-m', 'pip', 'install', name])
  

    
install('requests')
install('jsonpath_ng')
install('json')
install('base64')
install('warnings')
install('flask_sqlalchemy')
install('flask')
install('flask_restful')
install('cryptography')
