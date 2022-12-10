import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
import unittest
from maxmods.auth.imports.auth_function import *
test = authClass().Session()
id = Fernet.generate_key().hex()
id2 = Fernet.generate_key().hex()
hash = test.post('Greet', None, {'Id':id}).json()['Hash']
hash2 = test.post('Greet', None, {'Id':id2}).json()['Hash']
class testAuth(unittest.TestCase):
    def test_01(self):
        self.assertEqual(test.post('Signup', None, {'Username':''}).json()['Code'], 406)
    def test_02(self):
        self.assertEqual(test.post('Signup', None, {'Username':'$%^'}).json()['Code'], 406)
    def test_03(self):
        self.assertEqual(test.post('Signup', None, {'Username':'Test', 'Password':'Test'}).json()['Code'], 200)
    def test_04(self):
        self.assertEqual(test.post('Signup', None, {'Username':'Test'}).json()['Code'], 409)
    def test_05(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash , 'Username':'', 'Password':'Test'}).json()['Code'], 406)
    def test_06(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash , 'Username':'#@$%', 'Password':'Test'}).json()['Code'], 406)
    def test_07(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash , 'Username':'Test2', 'Password':'Test'}).json()['Code'], 404)
    def test_08(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash , 'Username':'Test', 'Password':'Test'}).json()['Code'], 200)
    def test_09(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash , 'Username':'Test', 'Password':'Test2'}).json()['Code'], 401)
    def test_10(self):
        self.assertEqual(test.post('Login', None, {'Id':id, 'Hash':hash2, 'Username':'Test', 'Password':'Test'}).json()['Code'], 423)
    def test_11(self):
        self.assertEqual(test.post('Save', None, {'Id':id, 'Hash':hash, 'Location':'', 'Data':''}).json()['Code'], 420)
    def test_12(self):
        self.assertEqual(test.post('Save', None, {'Id':id, 'Hash':hash, 'Location':'', 'Data':json.dumps('32')}).json()['Code'], 200)
    def test_13(self):
        self.assertEqual(test.post('Save', None, {'Id':id, 'Hash':hash2, 'Location':'', 'Data':json.dumps('32')}).json()['Code'], 423)
    def test_14(self):
        self.assertEqual(test.post('Load', None, {'Id':id, 'Hash':hash, 'Location':''}).json()['Code'], 202)
    def test_15(self):
        self.assertEqual(test.post('Load', None, {'Id':id, 'Hash':hash, 'Location':'bruh'}).json()['Code'], 416)
    def test_16(self):
        self.assertEqual(test.post('Load', None, {'Id':id, 'Hash':hash2, 'Location':'bruh'}).json()['Code'], 423)
    def test_96(self):
        self.assertEqual(test.post('Remove', None, {'Id':id, 'Hash':hash}).json()['Code'], 200)
    
if __name__ == '__main__':
    unittest.main()
