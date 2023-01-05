import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
import unittest
from maxmods.auth.main import *
test = frontend_session()
id = Fernet.generate_key().hex()
id2 = Fernet.generate_key().hex()
hash = test.post('create_session', None, {'id':id}).json()['hash']
hash2 = test.post('create_session', None, {'id':id2}).json()['hash']
class testAuth(unittest.TestCase):
    def test_01(self):
        self.assertEqual(test.post('sign_up', None, {'username':''}).json()['code'], 406)
    def test_02(self):
        self.assertEqual(test.post('sign_up', None, {'username':'$%^'}).json()['code'], 406)
    def test_03(self):
        self.assertEqual(test.post('sign_up', None, {'username':'Test', 'password':'Test'}).json()['code'], 200)
    def test_04(self):
        self.assertEqual(test.post('sign_up', None, {'username':'Test'}).json()['code'], 409)
    def test_05(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash , 'username':'', 'password':'Test'}).json()['code'], 406)
    def test_06(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash , 'username':'#@$%', 'password':'Test'}).json()['code'], 406)
    def test_07(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash , 'username':'Test2', 'password':'Test'}).json()['code'], 404)
    def test_08(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash , 'username':'Test', 'password':'Test'}).json()['code'], 200)
    def test_09(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash , 'username':'Test', 'password':'Test2'}).json()['code'], 401)
    def test_10(self):
        self.assertEqual(test.post('log_in', None, {'id':id, 'hash':hash2, 'username':'Test', 'password':'Test'}).json()['code'], 423)
    def test_11(self):
        self.assertEqual(test.post('save_data', None, {'id':id, 'hash':hash, 'location':'', 'data':''}).json()['code'], 420)
    def test_12(self):
        self.assertEqual(test.post('save_data', None, {'id':id, 'hash':hash, 'location':'ty', 'data':json.dumps('32')}).json()['code'], 200)
    def test_13(self):
        self.assertEqual(test.post('save_data', None, {'id':id, 'hash':hash2, 'location':'', 'data':json.dumps('32')}).json()['code'], 423)
    def test_14(self):
        self.assertEqual(test.post('load_data', None, {'id':id, 'hash':hash, 'location':''}).json()['code'], 202)
    def test_15(self):
        self.assertEqual(test.post('load_data', None, {'id':id, 'hash':hash, 'location':'bruh'}).json()['code'], 416)
    def test_16(self):
        self.assertEqual(test.post('load_data', None, {'id':id, 'hash':hash2, 'location':'bruh'}).json()['code'], 423)
    def test_17(self):
        self.assertEqual(test.post('delete_data', None, {'id':id, 'hash':hash, 'location':'ty'}).json()['code'], 200)
    def test_18(self):
        self.assertEqual(test.post('delete_data', None, {'id':id, 'hash':hash, 'location':''}).json()['code'], 200)
    def test_19(self):
        self.assertEqual(test.post('delete_data', None, {'id':id, 'hash':hash, 'location':'bruh'}).json()['code'], 416)
    def test_20(self):
        self.assertEqual(test.post('delete_data', None, {'id':id, 'hash':hash2, 'location':'bruh'}).json()['code'], 423)
    def test_96(self):
        self.assertEqual(test.post('remove_account', None, {'id':id, 'hash':hash}).json()['code'], 200)
    
if __name__ == '__main__':
    unittest.main()
