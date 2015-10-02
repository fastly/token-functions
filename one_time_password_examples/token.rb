require 'rubygems'
require 'base64'
require 'openssl'
require 'typhoeus'
 
encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q="
interval = 60
 
key = Base64.decode64(encodedkey)
 
number = Time.now.utc.to_i/interval
l = (number & 0xffffffff00000000) >>32
r = number & 0x00000000ffffffff

number = [r,l].pack('VV') 
 
digest = OpenSSL::HMAC.digest('sha256', key, number)
 
token = Base64.encode64(digest).strip()
 
response = Typhoeus::Request.get("http://token.fastly.com/token")
validation = Typhoeus::Request.get("http://token.fastly.com?#{token}")
 
p "Your Token:   #{token}"
p "Fastly Token: #{response.body}"
p "Validation:   #{validation.body}"
