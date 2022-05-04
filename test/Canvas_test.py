from MaxMods.Canvas import *
class handle:
    def __init__(self, Root):
        self.Root = Root
        self.stop1 = False
    def Main(self):
            self.Root.line(((200,100),(600,300)),'1')
    
drawer = Canvas(handle)