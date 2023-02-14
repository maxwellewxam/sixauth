poop = {
    'name1':{
        'data': 'anything1',
        'folder':{
            'name2':{
                'data': 'anything2',
                'folder':{}
            }
        }
    } 
}


def make_location(dict, path, data):
    path = path.split('/')
    for pos, name in enumerate(path):
        if not len([match for match in dict.keys() if match == name]) > 0:
            dict[name] = {'data': None, 'folder':{}}
        if len(path)==pos+1:
            dict[name]['data'] = data
            return
        dict = dict[name]['folder']
        
def find_data(dict, path):
    path = path.split('/')
    for pos, name in enumerate(path):
        if len(path)==pos+1:
            return dict[name]
        dict = dict[name]['folder']
        
def delete_location(dict, path):
    path = path.split('/')
    for pos, name in enumerate(path):
        if len(path)==pos+1:
            del dict[name]
            return {'code':200}
        dict = dict[name]['folder']
        
make_location(poop, 'name1/name2/bruh/poop', 'some text')
print(delete_location(poop, 'name1/name2'))
print(poop)