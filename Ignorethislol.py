import jsonpath_ng
# Initializing JSON data
json_data = {'foo': {'baz': 1, 'bazs': 2}}
# Setting up a parser
jsonpath_expr = [match.value for match in jsonpath_ng.parse('foo.bazs').find(json_data)][0]
# Parsing the values of JSON data
https://stackoverflow.com/questions/59057672/update-json-nodes-in-python-using-jsonpath #look here

print(jsonpath_expr)
print(jsonpath_ng.parse('foo.bazs').find(json_data))