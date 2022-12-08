
import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.auth import AuthSesh as ash
from maxmods.auth.imports import AuthenticationError, LocationError, warnings
import unittest
'https://127.0.0.1:5678/'
with ash() as user1, ash() as user2:

    class testAuth(unittest.TestCase):
        def test_111_login_client_side_wrong_username(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username does not exist')

        def test_112_login_client_side_no_username(self):
            user1.set_vals('', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Invalid username')
        
        def test_121_login_client_side_bad_pass(self):
            user1.set_vals('test', 'max')
            with self.assertRaises(AuthenticationError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Incorrect password')
        
        def test_113_signup_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.signup())
        
        def test_122_login_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.login())
        
        def test_123_signup_client_side_bad_username(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user1.signup()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username already exists')
        
        def test_131_save_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.save('Test/Test', 'UR MOM'))
        
        def test_132_load_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertEqual(user1.load('Test/Test'), 'UR MOM')
            
        def test_133_load_client_side_doesnt_exist(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(LocationError) as cm:
                user1.load('John/Green/Rubber/Co')
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Loaction does not exist')
            
        def test_134_save_client_side_whole_dict(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.save('', {'URMOM':'test'}))
            
        def test_135_load_client_side_all_data(self):
            user1.set_vals('test', 'test')
            self.assertEqual(user1.load(''), {'URMOM':'test'})
        
        def test_136_save_client_side_str(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.save('', 'comma'))

        def test_199_remove_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.remove())
        
        def test_211_login_server_side_wrong_username(self):
            warnings.filterwarnings('ignore')
            user2.set_vals('test', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user2.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username does not exist')

        def test_212_login_server_side_no_username(self):
            user2.set_vals('', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user2.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Invalid username')
        
        def test_221_login_server_side_bad_pass(self):
            user2.set_vals('test', 'max')
            with self.assertRaises(AuthenticationError) as cm:
                user2.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Incorrect password')
        
        def test_213_signup_server_side_success(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.signup())
        
        def test_222_login_server_side_success(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.login())
        
        def test_223_signup_server_side_bad_username(self):
            user2.set_vals('test', 'test')
            with self.assertRaises(AuthenticationError) as cm:
                user2.signup()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username already exists')
        
        def test_231_save_server_side_success(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.save('Test/Test', 'UR MOM'))
        
        def test_232_load_server_side_success(self):
            user2.set_vals('test', 'test')
            self.assertEqual(user2.load('Test/Test'), 'UR MOM')
            
        def test_233_load_server_side_doesnt_exist(self):
            user2.set_vals('test', 'test')
            with self.assertRaises(LocationError) as cm:
                user2.load('John/Green/Rubber/Co')
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Loaction does not exist')
            
        def test_234_save_server_side_whole_dict(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.save('', {'URMOM':'test'}))
            
        def test_235_load_server_side_all_data(self):
            user2.set_vals('test', 'test')
            self.assertEqual(user2.load(''), {'URMOM':'test'})
        
        def test_236_save_server_side_str(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.save('', 'comma'))
        
        def test_299_remove_server_side_success(self):
            user2.set_vals('test', 'test')
            self.assertTrue(user2.remove())
            
    if __name__ == '__main__':
        unittest.main()


