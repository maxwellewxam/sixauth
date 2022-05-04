from MaxMods.Canvas import *
class handle:
    def __init__(self, Root):
        self.Root = Root
    def Main(self):
            self.Root.triangle([[200,100],[450,300], [200,400]],1)
    
drawer = Canvas(handle, 600)