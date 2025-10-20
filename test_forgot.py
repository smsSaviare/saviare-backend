import requests

url = "http://127.0.0.1:5000/forgot-password"
data = {"username": "usuario@ejemplo.com"}

response = requests.post(url, json=data)
print(response.status_code)
print(response.text)
