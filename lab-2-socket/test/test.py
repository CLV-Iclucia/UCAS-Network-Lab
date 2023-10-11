import requests
from os.path import dirname, realpath

requests.packages.urllib3.disable_warnings()

test_dir = dirname(realpath(__file__))
print(test_dir)
timeout = 2 # 2 seconds
# http 301
r = requests.get('http://10.0.0.1/index.html', allow_redirects=False, timeout = timeout)
assert(r.status_code == 301 and r.headers['Location'] == 'https://10.0.0.1/index.html')
print("pass test 1!")
r = requests.get('http://10.0.0.1/notfound.html', verify=False, timeout = timeout)
assert(r.status_code == 404)
print("pass test 4!")
# https 200 OK
r = requests.get('https://10.0.0.1/index.html', verify=False, timeout = timeout)
# count the size of r.content
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("pass test 2!")
# http 200 OK
r = requests.get('http://10.0.0.1/index.html', verify=False, timeout = timeout)
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("pass test 3!")
# http 404
# file in directory
r = requests.get('http://10.0.0.1/dir/index.html', verify=False, timeout = timeout)
assert(r.status_code == 200 and open(test_dir + '/../index.html', 'rb').read() == r.content)
print("pass test 5!")
# http 206
headers = { 'Range': 'bytes=100-200' }
r = requests.get('http://10.0.0.1/index.html', headers=headers, verify=False, timeout = timeout)
assert(r.status_code == 206 and open(test_dir + '/../index.html', 'rb').read()[100:201] == r.content)

print("pass test 6!")
# http 206
headers = { 'Range': 'bytes=100-' }
r = requests.get('http://10.0.0.1/index.html', headers=headers, verify=False, timeout = timeout)
assert(r.status_code == 206 and open(test_dir + '/../index.html', 'rb').read()[100:] == r.content)

print("pass all tests!")