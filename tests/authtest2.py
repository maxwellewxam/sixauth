import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
import unittest
from maxmods.auth.main import *
test = frontend_session()
id = Fernet.generate_key().hex()
id2 = Fernet.generate_key().hex()
hash = test(func='create_session', id=id)['hash']
hash2 = test(func='create_session', id=id2)['hash']
class testAuth(unittest.TestCase):
    def test_01(self):
        self.assertEqual(test(func='sign_up', username='')['code'], 406)
    def test_02(self):
        self.assertEqual(test(func='sign_up', username='$%^')['code'], 406)
    def test_03(self):
        self.assertEqual(test(func='sign_up', username='Test', password='Test')['code'], 200)
    def test_04(self):
        self.assertEqual(test(func='sign_up', username='Test')['code'], 409)
    def test_05(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash , username='', password='Test')['code'], 406)
    def test_06(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash , username='#@$%', password='Test')['code'], 406)
    def test_07(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash , username='Test2', password='Test')['code'], 404)
    def test_08(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash , username='Test', password='Test')['code'], 200)
    def test_09(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash , username='Test', password='Test2')['code'], 401)
    def test_10(self):
        self.assertEqual(test(func='log_in', id=id, hash=hash2, username='Test', password='Test')['code'], 423)
    def test_11(self):
        self.assertEqual(test(func='save_data', id=id, hash=hash, location='', data='')['code'], 420)
    def test_12(self):
        self.assertEqual(test(func='save_data', id=id, hash=hash, location='ty', data=json.dumps('32'))['code'], 200)
    def test_13(self):
        self.assertEqual(test(func='save_data', id=id, hash=hash2, location='', data=json.dumps('32'))['code'], 423)
    def test_14(self):
        self.assertEqual(test(func='load_data', id=id, hash=hash, location='')['code'], 202)
    def test_15(self):
        self.assertEqual(test(func='load_data', id=id, hash=hash, location='bruh')['code'], 416)
    def test_16(self):
        self.assertEqual(test(func='load_data', id=id, hash=hash2, location='bruh')['code'], 423)
    def test_17(self):
        self.assertEqual(test(func='log_out', id=id, hash=hash)['code'], 200)
    def test_18(self):
        self.assertEqual(test(func='log_out', id=id, hash=hash2)['code'], 200)
    def test_21(self):
        self.assertEqual(test(func='end_session', id=id, hash=hash)['code'], 200)
    def test_19(self):
        self.assertEqual(test(func='end_session', id=id, hash=hash2)['code'], 423)
    def test_20(self):
        self.assertEqual(test(func='remove_account', id=id, hash=hash)['code'], 200)
    
if __name__ == '__main__':
    unittest.main()
