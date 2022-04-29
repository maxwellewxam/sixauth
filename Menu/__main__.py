import os
class CallerError(Exception): ...
class Base:
    def __init__(self, Title = None, Class = None, Item = None):
        self.Title = Title
        self.Class = Class
        if Item is None:
            self.Item = [[0, 'Exit', (None, None), {}]]
        else: self.Item = Item
    def add_item(self, Caller, Text, *args, **kwargs):
        for item in self.Item:
            if item[0] == Caller:
                raise CallerError('Defined Caller is already in use.')
        row = [Caller, Text, args, kwargs]
        self.Item.append(row)
    def update_item(self, Caller, Text, *args, **kwargs):
        self.remove_item(Caller)
        row = [Caller, Text, args, kwargs]
        self.Item.append(row)
    def remove_item(self, Caller):
        for item in self.Item:
            if item[0] == Caller:
                self.Item.remove(item)
    def Refresh(self):
        os.system('cls')
    def Run(self, Caller = 0, inText = 'Selection: '):
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
            choice = str(input(inText))
            self.Refresh()
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
            self.Refresh()
            self.Run()
        except Exception as err:
            print(err)
            input()
            self.Refresh()
            self.Run()
class basicMenu(Base):
    def __init__(self, Title: str):
        super().__init__(Title = Title)
    def add_item(self, Caller: int, Text: str, Func: object, *args, **kwargs):
        super().add_item(Caller, Text, Func, *args, **kwargs)
    def update_item(self, Caller: int, Text: str, Func: object, *args, **kwargs):
        super().update_item(Caller, Text, Func, *args, **kwargs)
    def Run(self):
        super().Run()
class infoMenu(Base):
    def __init__(self, Title: str, Class: object):
        super().__init__(Title = Title, Class = Class, Item = [])
    def add_item(self, Caller: int, Text: str, Attr: str):
        super().add_item(Caller, Text, Attr)
    def update_item(self, Caller: int, Text: str, Attr: str):
        super().update_item(Caller, Text, Attr)
    def Run(self):
        super().Run(Caller=1, inText='Enter to Continue')
class settingsMenu(Base):
    def __init__(self, Title: str, Class: object):
        super().__init__(Title = Title, Class = Class)
    def add_item(self, Caller: int, Text: str, Attr: str):
        super().add_item(Caller, Text, self.ChangeVal, Attr)
    def update_item(self, Caller: int, Text: str, Attr: str):
        super().update_item(Caller, Text, self.ChangeVal, Attr)
    def Run(self):
        super().Run(Caller=2)
    def ChangeVal(self, attr):
        new = input('New Value: ')
        setattr(self.Class, attr, new)