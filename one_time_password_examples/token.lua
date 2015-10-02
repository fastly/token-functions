os = require "os"
bit = require "bit"
crypto = require "crypto"
http = require "socket.http"
math = require "math"

-- character table string
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

function rtrim(s)
  local n = #s
  while n > 0 and s:find("^%s", n) do n = n - 1 end
  return s:sub(1, n)
end

-- encoding
function base64encode(data)
    return ((data:gsub('.', function(x) 
        local r,b='',x:byte()
        for i=8,1,-1 do r=r..(b%2^i-b%2^(i-1)>0 and '1' or '0') end
        return r;
    end)..'0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if (#x < 6) then return '' end
        local c=0
        for i=1,6 do c=c+(x:sub(i,i)=='1' and 2^(6-i) or 0) end
        return b:sub(c+1,c+1)
    end)..({ '', '==', '=' })[#data%3+1])
end

-- decoding
function base64decode(data)
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        return string.char(c)
    end))
end

function encode_int(n)
  local a = bit.band(n, 0xff)
  local b = bit.band(bit.rshift(n, 8), 0xff)
  local c = bit.band(bit.rshift(n, 16), 0xff)
  local d = bit.band(bit.rshift(n, 24), 0xff)
  return string.char(a, b, c, d)
end

local encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q="
local interval = 60
 
local key = base64decode(encodedkey)
 
local number = math.floor(os.time()/interval)

-- l is shifted right by 32 bits
local l = bit.band(number, 0xffffffff00000000) / 2^32
local r = bit.band(number, 0x00000000ffffffff)

number = encode_int(r) .. encode_int(l)

local digest = crypto.hmac.digest("sha256", number, key, true)

local token = rtrim(base64encode(digest))
 
local response = http.request("http://token.fastly.com/token")
local validation = http.request("http://token.fastly.com?" .. token)

print("Your Token: " .. token)
print("Fastly token: " .. response)
print("Validation: ")
print(validation)
