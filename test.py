import Auth

class MainApp:
    def __init__(self) -> None:
        self.startloop()
        
    def startloop(self) -> None:
        print('Welcome')
        username = str(input('Enter Username: '))
        password = str(input('Enter Password: '))
        self.log = Auth.Auth()
        self.log.set_auth_values(Name=username, Pass=password)
        try:
            self.arf = self.log.Login()
            self.mainloop()
        except Auth.AuthenticationError as err:
            if str(err) == 'Username does not exist':
                try:
                    self.log.Signup()
                except Auth.AuthenticationError as err:
                    print(err)
            else: print(err)
            del(self.log)
            self.startloop()
        
    def mainloop(self):
        stay = str(input('Continue? (y|n): '))
        if stay == 'y':
            if self.arf == True:
                choice = str(input('Would you like to save or load data? (l|s): '))
                if choice == 'l':
                    try:
                        location = str(input('Load from where? (ex: Data/john/local/ur mom): '))
                        data = self.log.Load(location)
                        print(data)
                        self.mainloop()
                    except Auth.LocationError as err:
                        if str(err) == 'Loaction does not exist':
                            print(err)
                        elif str(err) == 'Cannot access type \'str\'':
                            print('invalid location')
                        else:
                            print(err)
                        self.mainloop()
                    except Auth.AuthenticationError as err:
                        print(err)
                        self.startloop()
                elif choice == 's':
                    try:
                        location = str(input('Save to where? (ex: Data/john/local/ur mom): '))
                        data = str(input('What to save: '))
                        self.log.Save(location, data)
                        print('Success')
                        self.mainloop()
                    except Auth.LocationError as err:
                        print(err)
                        self.mainloop()
                    except Auth.AuthenticationError as err:
                        print(err)
                        self.startloop()
        elif stay == 'n':
            pass
        else:
            self.mainloop()
            
MainApp()
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy
i will not be a bad boy