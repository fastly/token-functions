import base64
import hmac, hashlib
import time
import urllib2
import struct

encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q="
interval = 60

key = base64.b64decode(encodedkey)
number = struct.pack('<Q', int(time.time()) / interval)
digest = hmac.new(key, number, hashlib.sha256).digest()
token = base64.b64encode(digest)

response = urllib2.urlopen("http://token.fastly.com/token")
validation = urllib2.urlopen("http://token.fastly.com?{0}".format(token))

print "Your Token:   {0}".format(token)
print "Fastly Token: {0}".format(response.read())
print "Validation:   {0}".format(validation.read())
