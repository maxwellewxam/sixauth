import subprocess
import sys
subprocess.check_call([sys.executable, "-m", "pip", "uninstall", 'certifi'])
subprocess.check_call([sys.executable, "-m", "pip", "install", 'certifi'])
import certifi
cafile = certifi.where()
with open('server-public-key.pem', 'rb') as infile:
    customca = infile.read()
with open(cafile, 'ab') as outfile:
    outfile.write(customca)