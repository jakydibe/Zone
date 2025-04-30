import requests

url = "https://www.virustotal.com/api/v3/0d34c5586de47cc2a170f138784dbb76ef08699b524207c0095a321f6265ff20/overall_quotas"

headers = {"accept": "application/json"}

response = requests.get(url, headers=headers)

print(response.text)