import base64
import hmac, hashlib
import time
import urllib.request
import struct


encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q="
interval = 60

key = base64.b64decode(encodedkey)
number = struct.pack('<Q', int(time.time() / interval))
digest = hmac.new(key, number, hashlib.sha256).digest()
token = base64.b64encode(digest)

response = urllib.request.urlopen('http://token.fastly.com/token')
validation = urllib.request.urlopen('http://token.fastly.com?{0}'.format(str(token, 'utf-8')))

print("Your Token:   {0}".format(token))
print("Fastly Token: {0}".format(response.read()))
print("Validation:   {0}".format(validation.read()))


