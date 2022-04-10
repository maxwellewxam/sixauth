import Auth
class MainApp:
    def __init__(self) -> None:
        self.mainloop()
    def mainloop(self) -> None:
        print('Welcome')
        username = str(input('Enter Username: '))
        password = str(input('Enter Password: '))
        log = Auth.Auth(Name=username, Pass=password)
        try:
            log.Login()
        except Auth.AuthenticationError as err:
            if str(err) == 'Username does not exist':
                try:
                    log.Signup()
                except Auth.AuthenticationError as err:
                    print(err)
            else: print(err)
        
MainApp()