import Auth
import unittest

class testAuth(unittest.TestCase):
    user1 = Auth.Auth()
    user2 = Auth.Auth('https://localhost:5678/')
    def test_111_login_client_side_wrong_username(self):
        self.user1.get_vals('test', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user1.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username does not exist')

    def test_112_login_client_side_no_username(self):
        self.user1.get_vals('', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user1.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Invalid username')
    
    def test_113_login_client_side_bad_pass(self):
        self.user1.get_vals('max', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user1.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Incorrect password')
    
    def test_121_signup_client_side_success(self):
        self.user1.get_vals('test', 'test')
        self.assertTrue(self.user1.Signup())
    
    def test_122_login_client_side_success(self):
        self.user1.get_vals('test', 'test')
        self.assertTrue(self.user1.Login())
    
    def test_123_signup_client_side_bad_username(self):
        self.user1.get_vals('test', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user1.Signup()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username already exists')
    
    def test_131_save_client_side_success(self):
        self.user1.get_vals('test', 'test')
        self.assertTrue(self.user1.Save('Test/Test', 'UR MOM'))
    
    def test_132_load_client_side_success(self):
        self.user1.get_vals('test', 'test')
        self.assertEqual(self.user1.Load('Test/Test'), 'UR MOM')
        
    def test_133_load_client_side_doesnt_exist(self):
        self.user1.get_vals('test', 'test')
        with self.assertRaises(Auth.LocationError) as cm:
            self.user1.Load('John/Green/Rubber/Co')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Loaction does not exist')
        
    def test_134_save_client_side_whole_dict(self):
        self.user1.get_vals('test', 'test')
        self.assertTrue(self.user1.Save('', {'URMOM':'test'}))
        
    def test_135_load_client_side_all_data(self):
        self.user1.get_vals('test', 'test')
        self.assertEqual(self.user1.Load(''), {'URMOM':'test'})
    
    def test_136_save_client_side_str(self):
        self.user1.get_vals('test', 'test')
        with self.assertRaises(Auth.LocationError) as cm:
            self.user1.Save('', 'comma')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Cannot access type \'str\'')
    
    def test_199_remove_client_side_success(self):
        self.user1.get_vals('test', 'test')
        self.assertTrue(self.user1.Remove_User())
    
    def test_211_login_server_side_wrong_username(self):
        self.user2.get_vals('test', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user2.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username does not exist')

    def test_212_login_server_side_no_username(self):
        self.user2.get_vals('', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user2.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Invalid username')
    
    def test_213_login_server_side_bad_pass(self):
        self.user2.get_vals('max', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user2.Login()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Incorrect password')
    
    def test_221_signup_server_side_success(self):
        self.user2.get_vals('test', 'test')
        self.assertTrue(self.user2.Signup())
    
    def test_222_login_server_side_success(self):
        self.user2.get_vals('test', 'test')
        self.assertTrue(self.user2.Login())
    
    def test_223_signup_server_side_bad_username(self):
        self.user2.get_vals('test', 'test')
        with self.assertRaises(Auth.AuthenticationError) as cm:
            self.user2.Signup()
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Username already exists')
    
    def test_231_save_server_side_success(self):
        self.user2.get_vals('test', 'test')
        self.assertTrue(self.user2.Save('Test/Test', 'UR MOM'))
    
    def test_232_load_server_side_success(self):
        self.user2.get_vals('test', 'test')
        self.assertEqual(self.user2.Load('Test/Test'), 'UR MOM')
        
    def test_233_load_server_side_doesnt_exist(self):
        self.user2.get_vals('test', 'test')
        with self.assertRaises(Auth.LocationError) as cm:
            self.user2.Load('John/Green/Rubber/Co')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Loaction does not exist')
        
    def test_234_save_server_side_whole_dict(self):
        self.user2.get_vals('test', 'test')
        self.assertTrue(self.user2.Save('', {'URMOM':'test'}))
        
    def test_235_load_server_side_all_data(self):
        self.user2.get_vals('test', 'test')
        self.assertEqual(self.user2.Load(''), {'URMOM':'test'})
    
    def test_236_save_server_side_str(self):
        self.user2.get_vals('test', 'test')
        with self.assertRaises(Auth.LocationError) as cm:
            self.user2.Save('', 'comma')
        the_exception = cm.exception
        self.assertEqual(str(the_exception), 'Cannot access type \'str\'')
    
    def test_299_remove_server_side_success(self):
        self.user2.get_vals('test', 'test')
        self.assertTrue(self.user2.Remove_User())
        
if __name__ == '__main__':
    unittest.main()


