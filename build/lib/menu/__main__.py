import os
class CallerError(BaseException): ...
class MenuException(BaseException): ...
class Base:
    def __init__(self, Title = None, Class = None, Item = None, inText = 'Selection: '):
        '''
        Underlying Base class of all Menu objects.
        '''
        self.Title = Title
        self.Class = Class
        self.inText = inText
        if Item is None:
            self.Item = [[0, 'Exit', (None, None), {}]]
        else: self.Item = Item
    def add_item(self, Caller, Text, *args, **kwargs):
        '''
        Adds an item to the menu at the specified Caller
        
        Raises an exception if the position is already occupied
        '''
        for item in self.Item:
            if item[0] == Caller:
                raise CallerError('Defined Caller is already in use.')
        row = [Caller, Text, args, kwargs]
        self.Item.append(row)
    def update_item(self, Caller, Text, *args, **kwargs):
        '''
        Updates item on the menu with specified Caller
        
        Raises an exception if the Caller does not exist
        '''
        self.remove_item(Caller)
        row = [Caller, Text, args, kwargs]
        self.Item.append(row)
    def remove_item(self, Caller):
        '''
        Removes item with specified Caller
        
        Raises an Exception if Caller does not exist
        '''
        for item in self.Item:
            if item[0] == Caller:
                self.Item.remove(item)
                return
        raise CallerError('Defined Caller does not exist')
    def __Refresh(self):
        os.system('cls')
    def run(self, Caller = 0):
        '''
        Creates the menu and Runs it
        
        Handles Menu exceptions and prints them to screen
        '''
        self.__Refresh()
        text = f'{self.Title}\n'
        self.Item.sort(key=lambda x:x[0])
        for i, item in enumerate(self.Item):
            if Caller == 0 or item[0] == 0:
                text += f'{i} | {item[1]}'
            elif Caller == 1:
                val = str(getattr(self.Class, *item[2]))
                text += f'{item[1]}: {val}'
            elif Caller == 2:
                _, attr = item[2]
                val = str(getattr(self.Class, attr))
                text += f'{i} | {item[1]}: {val}'
            if i+1 != len(self.Item):
                text += '\n'
        print(text)
        try:
            choice = str(input(self.inText))
            self.__Refresh()
            for item in self.Item:
                if str(item[0]) == choice:
                    func, *args = item[2]
                    if callable(func):
                        func(*args, **item[3])
                        break
                    else:
                        return
                elif '' == choice and Caller == 1:
                    return
            self.Run()
        except MenuException as err:
            print(err)
            input()
            self.Run()
class BasicMenu(Base):
    def __init__(self, Title: str):
        '''
        Creates a menu object
        
        Most basic form of menu
        '''
        super().__init__(Title = Title)
    def add_item(self, Caller: int, Text: str, Func: object, *args, **kwargs):
        '''
        Adds an item to the menu at the specified Caller
        
        Raises an exception if the Caller is already occupied
        '''
        super().add_item(Caller, Text, Func, *args, **kwargs)
    def update_item(self, Caller: int, Text: str, Func: object, *args, **kwargs):
        '''
        Updates item on the menu with specified Caller
        
        Raises an exception if the Caller does not exist
        '''
        super().update_item(Caller, Text, Func, *args, **kwargs)
        
class InfoMenu(Base):
    def __init__(self, Title: str, Class: object):
        '''
        Creates a menu object that does not except a user input
        
        used for displaying info in a style similar to the rest of the menus
        '''
        super().__init__(Title = Title, Class = Class, Item = [])
    def add_item(self, Caller: int, Text: str, Attr: str):
        '''
        Adds an item to the menu at the specified Caller
        
        Raises an exception if the position is already occupied
        '''
        super().add_item(Caller, Text, Attr)
    def update_item(self, Caller: int, Text: str, Attr: str):
        '''
        Updates item on the menu with specified Caller
        
        Raises an exception if the Caller does not exist
        '''
        super().update_item(Caller, Text, Attr)
    def run(self):
        '''
        Creates the menu and Runs it
        
        Handles all exceptions and prints them to screen
        '''
        self.inText='Enter to Continue'
        super().run(Caller=1)
class SettingsMenu(Base):
    def __init__(self, Title: str, Class: object):
        '''
        Creats a menu object
        
        defined attr in add_item will be changed to user defined value when selected
        '''
        super().__init__(Title = Title, Class = Class)
    def add_item(self, Caller: int, Text: str, Attr: str):
        '''
        Adds an item to the menu at the specified Caller
        
        Raises an exception if the position is already occupied
        '''
        super().add_item(Caller, Text, self.__ChangeVal, Attr)
    def update_item(self, Caller: int, Text: str, Attr: str):
        '''
        Updates item on the menu with specified Caller
        
        Raises an exception if the Caller does not exist
        '''
        super().update_item(Caller, Text, self.__ChangeVal, Attr)
    def run(self):
        '''
        Creates the menu and Runs it
        
        Handles all exceptions and prints them to screen
        '''
        super().run(Caller=2)
    def __ChangeVal(self, attr):
        new = input('New Value: ')
        setattr(self.Class, attr, new)