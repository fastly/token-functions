### Token Authentication

Tokens give you the ability to create URLs that expire. If you only want to give a particular user access to a link for a specific amount of time, you'll need tokens. They're commonly used to secure video assets, but you can create and validate signatures to be transferred in other ways, like cookies or authentication headers.

#### Table of Contents
* [VCL](#vcl)
* Code Examples
 * [Python](#python)
 * [Ruby](#ruby)
 * [PHP](#php)
 * [Go](#go)
 * [C#](#c)

#### VCL

The code that enables token auth should be placed in `vcl_recv`. This is an example:

```vcl
  /* extract token signature and expiration */
  set req.http.X-Token = urldecode(regsub(req.url, ".*token=([^&]+)(?:&|$).*", "\1"));
  set req.http.X-Sig = regsub(req.http.X-Token, "^[^_]+_(.*)", "\1");
  set req.http.X-Exp = regsub(req.http.X-Token, "^([^_]+)_.*", "\1");

  /* validate signature */
  if (req.http.X-Sig == regsub(digest.hmac_sha1(digest.base64_decode("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24="),
  req.url.path req.http.X-Exp), "^0x", "")) {

    /* use vcl time math to check expiration timestamp */
    set req.http.X-Original-Grace = req.grace;
    set req.grace = std.atoi(strftime({"%s"}, now));
    set req.grace -= std.atoi(req.http.X-Exp);
    
    if (std.atoi(req.grace) > 0) {
      error 410;
    }
    
    /* clean up grace since we used it for time math */
    set req.grace = std.atoi(req.http.X-Original-Grace);
    unset req.http.X-Original-Grace;

  } else {
    error 403;
  }

  /* cleanup variables */
  unset req.http.X-Token;
  unset req.http.X-Sig;
  unset req.http.X-Exp;
```

This code expects to find a token in the `?token=` GET parameter. Tokens take the format of `[expiration]_[signature]` and look like this: `1441307151_4492f25946a2e8e1414a8bb53dab8a6ba1cf4615`. The full request URL would look like this: 

`http://www.example.com/foo/bar.html?token=1441307151_4492f25946a2e8e1414a8bb53dab8a6ba1cf4615`.

The key found in `digest.hmac_sha1` can be any string. This one was generated with the command `openssl rand -base64 32`.

The VCL checks for two things:

 1. Is the current time greater than the expiration time specified in the token?
 2. Does our signature match the signature of the token?

If the signature is invalid, Varnish will return a 403. If the signature is valid but the expiration time has elapsed, Varnish will return a 410. The different response codes are helpful for debugging (and also "more correct"). It is not possible for a malicious user to modify the expiration time of their token--if they did the signature would no longer match. 

#### Client Side Scripts

The client or web application will need to be able to generate tokens to authenticate with Varnish. 

##### Python

```python
import hmac
from hashlib import sha1
import time
import urllib
import base64

key = base64.b64decode("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = int(time.time()) + token_lifetime

string_to_sign = "{0}{1}".format(path,expiration)

digest = hmac.new(key, string_to_sign, sha1)

signature = digest.hexdigest() 

token = "{0}_{1}".format(expiration, urllib.quote(signature))

print "Token:   " + token
```

##### Ruby

```ruby
require 'base64'
require 'uri'
require 'openssl' 

key = Base64.decode64("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = Time.now.to_i + token_lifetime

string_to_sign = path+expiration.to_s

signature = OpenSSL::HMAC.hexdigest('sha1', key, string_to_sign)

token = expiration.to_s + "_" + URI.escape(signature)

puts "Token:   " + token
```

##### PHP

```php
<?php
$key = base64_decode("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=");
 
$token_lifetime = 1209600; # 2 weeks

$path = "/foo/bar.html";

$expiration = time() + $token_lifetime;

$string_to_sign = $path . $expiration;

$signature = hash_hmac('sha1', $string_to_sign, $key);

$token = $expiration . "_" . urlencode($signature);

print("Token:   " . $token . "\n");
?>
```

##### Go

```go
// this example can be modified and run at https://play.golang.org/p/BYXqllJy_J

package main

import (
    "crypto/hmac"
    "crypto/sha1"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "time"
)

const (
    encodedKey    = "iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24="
    tokenLifetime = 14 * 24 * time.Hour
    path          = "/foo/bar.html"
)

func main() {
    key, err := base64.StdEncoding.DecodeString(encodedKey)
    if err != nil {
        fmt.Println("key in not in base64: ", err)
        return
    }

    expiration := time.Now().Add(tokenLifetime).Unix()

    h := hmac.New(sha1.New, key)
    fmt.Fprintf(h, "%s%d", path, expiration)
    signature := hex.EncodeToString(h.Sum(nil))
    token := fmt.Sprintf("%d_%s", expiration, signature)

    fmt.Printf("Token: %s\n", token)
}
```

##### C♯

```csharp
// I've never written C# before. Apologies if this poor. --@stephenbasile

using System;
using System.Security.Cryptography;

byte[] key = Convert.FromBase64String("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=");

Int32 lifetime = 1209600;

string path = "/foo/bar.html";

Int32 expiration = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

expiration += lifetime;

string string_to_sign = path + expiration.ToString();

var encoding = new System.Text.UTF8Encoding();
byte[] messageBytes = encoding.GetBytes(string_to_sign);
using (var hmacsha1 = new HMACSHA1(key))
{
	byte[] hashmessage = hmacsha1.ComputeHash(messageBytes);
	Console.WriteLine(expiration + "_" + BitConverter.ToString(hashmessage).Replace("-", string.Empty).ToLower());
}
```
