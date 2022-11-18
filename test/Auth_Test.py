from maxmods.auth import *
import unittest


class testAuth(unittest.TestCase):
    user1 = AuthSesh()
    user2 = AuthSesh('https://localhost:5678/')
    def test_111_login_client_side_wrong_username(self):
        self.user1.set_vals('test', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user1.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username does not exist')

    def test_112_login_client_side_no_username(self):
        self.user1.set_vals('', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user1.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Invalid username')
    
    def test_121_login_client_side_bad_pass(self):
        self.user1.set_vals('test', 'max')
        with self.assertRaises(AuthenticationError) as cm:
            self.user1.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Incorrect password')
    
    def test_113_signup_client_side_success(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.signup())
    
    def test_122_login_client_side_success(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.login())
    
    def test_123_signup_client_side_bad_username(self):
        self.user1.set_vals('test', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user1.signup()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username already exists')
    
    def test_131_save_client_side_success(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.save('Test/Test', 'UR MOM'))
    
    def test_132_load_client_side_success(self):
        self.user1.set_vals('test', 'test')
        self.assertEqual(self.user1.load('Test/Test'), 'UR MOM')
        
    def test_133_load_client_side_doesnt_exist(self):
        self.user1.set_vals('test', 'test')
        with self.assertRaises(LocationError) as cm:
            self.user1.load('John/Green/Rubber/Co')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Loaction does not exist')
        
    def test_134_save_client_side_whole_dict(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.save('', {'URMOM':'test'}))
        
    def test_135_load_client_side_all_data(self):
        self.user1.set_vals('test', 'test')
        self.assertEqual(self.user1.load(''), {'URMOM':'test'})
    
    def test_136_save_client_side_str(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.save('', 'comma'))

    def test_199_remove_client_side_success(self):
        self.user1.set_vals('test', 'test')
        self.assertTrue(self.user1.remove())
    
    def test_211_login_server_side_wrong_username(self):
        self.user2.set_vals('test', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user2.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username does not exist')

    def test_212_login_server_side_no_username(self):
        self.user2.set_vals('', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user2.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Invalid username')
    
    def test_221_login_server_side_bad_pass(self):
        self.user2.set_vals('test', 'max')
        with self.assertRaises(AuthenticationError) as cm:
            self.user2.login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Incorrect password')
    
    def test_213_signup_server_side_success(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.signup())
    
    def test_222_login_server_side_success(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.login())
    
    def test_223_signup_server_side_bad_username(self):
        self.user2.set_vals('test', 'test')
        with self.assertRaises(AuthenticationError) as cm:
            self.user2.signup()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username already exists')
    
    def test_231_save_server_side_success(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.save('Test/Test', 'UR MOM'))
    
    def test_232_load_server_side_success(self):
        self.user2.set_vals('test', 'test')
        self.assertEqual(self.user2.load('Test/Test'), 'UR MOM')
        
    def test_233_load_server_side_doesnt_exist(self):
        self.user2.set_vals('test', 'test')
        with self.assertRaises(LocationError) as cm:
            self.user2.load('John/Green/Rubber/Co')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Loaction does not exist')
        
    def test_234_save_server_side_whole_dict(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.save('', {'URMOM':'test'}))
        
    def test_235_load_server_side_all_data(self):
        self.user2.set_vals('test', 'test')
        self.assertEqual(self.user2.load(''), {'URMOM':'test'})
    
    def test_236_save_server_side_str(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.save('', 'comma'))
    
    def test_299_remove_server_side_success(self):
        self.user2.set_vals('test', 'test')
        self.assertTrue(self.user2.remove())
        
if __name__ == '__main__':
    unittest.main()


