import requests
Base = 'http://127.0.0.1:5678/'
response = requests.get(Base+'12-30')
print(response.json())