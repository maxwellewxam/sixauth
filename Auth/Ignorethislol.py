from MaxMods.Auth import *
from urllib.request import urlopen
urlopen('https://www.howsmyssl.com/a/check').read()
class MainApp:
    def __init__(self) -> None:
        self.startloop()
        
    def startloop(self) -> None:
        print('Welcome')
        username = str(input('Enter Username: '))
        password = str(input('Enter Password: '))
        self.log = AuthSesh()
        self.log.get_vals(Name=username, Pass=password)
        try:
            self.arf = self.log.Login()
            self.mainloop()
        except AuthenticationError as err:
            if str(err) == 'Username does not exist':
                try:
                    self.log.Signup()
                    self.mainloop()
                except AuthenticationError as err:
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
                    except LocationError as err:
                        if str(err) == 'Loaction does not exist':
                            print(err)
                        elif str(err) == 'Cannot access type \'str\'':
                            print('invalid location')
                        else:
                            print(err)
                        self.mainloop()
                    except AuthenticationError as err:
                        print(err)
                        self.startloop()
                elif choice == 's':
                    try:
                        location = str(input('Save to where? (ex: Data/john/local/ur mom): '))
                        data = str(input('What to save: '))
                        self.log.Save(location, data)
                        print('Success')
                        self.mainloop()
                    except LocationError as err:
                        print(err)
                        self.mainloop()
                    except AuthenticationError as err:
                        print(err)
                        self.startloop()
                elif choice == 'r':
                    self.log.Remove_User()
                    print('success')
        elif stay == 'n':
            pass
        else:
            self.mainloop()
            
MainApp()
