
import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
sys.path.reverse()
from sixauth.auth import Authenticator as Auth
from sixauth.database import Database

db = Database(os.getcwd())
auth = Auth(db)

sys.exit(0)


logger.setup_logger(log_sensitive = True, log_more = True)
import unittest
# '127.0.0.1:5678'
with ash('127.0.0.1:5678') as user1:

    class testAuth(unittest.TestCase):
        def test_111_login_client_side_wrong_username(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username does not exist')

        def test_112_login_client_side_no_username(self):
            user1.set_vals('', 'test')
            with self.assertRaises(AuthError) as cm:
                user1.login()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Invalid username')
        
        def test_121_login_client_side_bad_pass(self):
            user1.set_vals('test', 'max')
            with self.assertRaises(AuthError) as cm:
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
            with self.assertRaises(AuthError) as cm:
                user1.signup()
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Username "test" already exists')
        
        def test_131_save_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.save('Test/Test', 'UR MOM'))
        
        def test_132_load_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertEqual(user1.load('Test/Test'), 'UR MOM')
            
        def test_133_load_client_side_doesnt_exist(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthError) as cm:
                user1.load('John/Green/Rubber/Co')
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'Location does not exist')
            
        def test_134_save_client_side_whole_dict(self):
            user1.set_vals('test', 'test')
            with self.assertRaises(AuthError) as cm:
                user1.save('', {'URMOM':'test'})
            the_exception = cm.exception
            self.assertEqual(str(the_exception), 'No path specified')
            
        def test_135_load_client_side_all_data(self):
            user1.set_vals('test', 'test')
            self.assertEqual(user1.load(''), {'Test': {'data': None, 'folder': {'Test': {'data': 'UR MOM', 'folder': {}}}}})

        def test_199_remove_client_side_success(self):
            user1.set_vals('test', 'test')
            self.assertTrue(user1.remove())
            
    if __name__ == '__main__':
        unittest.main()
