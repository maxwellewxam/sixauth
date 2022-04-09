import jsonpath_ng
# Initializing JSON data
json_data = {}
# Setting up a parser
jsonpath_ng.parse('foo.baz.hmmm').update_or_create(json_data, 'new')
jsonpath_expr = [match.value for match in jsonpath_ng.parse('foo.baz').find(json_data)][0]
print(jsonpath_expr)
bruh = ['foo', 'bar', 'fat']

#jsonpath_ng.Child(jsonpath_ng.Fields('baz'), jsonpath_ng.Fields(*'foo/bar/urmom'.replace('/', '.').split('.'))).update_or_create(json_data, 'new')
#jsonpath_expr = [match.value for match in jsonpath_ng.parse('foo.bazs.bruh.here').find_or_create(json_data)][0]
print(jsonpath_expr)
# Parsing the values of JSON data
#https://stackoverflow.com/questions/59057672/update-json-nodes-in-python-using-jsonpath look here
print(json_data) 