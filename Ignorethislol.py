class tree(dict):
    def __setitem__(self, key, value):
        if key[0] == '/' : key = key[1:]
        parts = key.split('/', 1)
        if len(parts) == 2:
            if parts[0] not in self: self[parts[0]] = tree()
            self[parts[0]].__setitem__(parts[1], value)
        else:
            super(tree, self).__setitem__(key, value)

    def __getitem__(self, key):
        if key[0] == '/' : key = key[1:]
        parts = key.split('/', 1)
        if len(parts) == 2:
            if parts[0] not in self: raise KeyError(parts[0])
            return self[parts[0]][parts[1]]
        else:
            if key not in self: raise KeyError(parts[0])
            return super(tree, self).__getitem__(key)
    def __contains__(self,key):
        if key[0] == '/' : key = key[1:]
        parts = key.split('/', 1)
        if len(parts) == 2:
            if not super(tree, self).__contains__(parts[0]): return False
            return parts[1] in self[parts[0]]
        else:
            if not super(tree, self).__contains__(key): return False
            return True
    def __delitem__(self, key):
        if key[0] == '/' : key = key[1:]
        parts = key.split('/', 1)
        if len(parts) == 2:
            if parts[0] not in self: raise KeyError(parts[0])
            self[parts[0]].__delitem__(parts[1])
        else:
            if key not in list(self): raise KeyError(parts[0])
            super(tree,self).__delitem__(key)
    def __iter__(self, parent=""):
        for name in super(tree, self).keys():
            if isinstance(self[name], tree):
                for item in self[name].__iter__(parent=parent+'/'+name):
                    yield item
            else:
                yield parent+'/'+name
    def keys(self,parent=""):
        names = []
        for name in super(tree, self).keys():
            if isinstance(self[name], tree):
                names += self[name].keys(parent=parent+'/'+name)
            else:
                names.append(parent+'/'+name)
        return names
#class Foo(dict):
#    def __setitem__(self, key, value):
#        parts = key.split('/', 1)
#        if len(parts) == 2:
#            if parts[0] not in self:
#                self[parts[0]] = Foo()
#            self[parts[0]].__setitem__(parts[1], value)
#        else:
#            super(Foo, self).__setitem__(key, value)

    #def __getitem__(self, key):
    #    parts = key.split('/', 1)
    #    if len(parts) == 2:
    #        return self[parts[0]][parts[1]]
    #    else:
    #        return super(Foo, self).__getitem__(key)
new = tree({'test':{'fart':'part'}})
print(new)
new['test/Data/fuck me/please/more'] = '42'
new['test/Data/fuck me/please/less'] = '42'
dic = new['test']
print(dic)