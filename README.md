### Token Authentication

Tokens give you the ability to create URLs that expire. If you only want to give a particular user access to a link for a specific amount of time, you'll need tokens. They're commonly used to secure video assets, but you can create and validate signatures to be transferred in other ways, like cookies or authentication headers.

#### Table of Contents
* [VCL](#vcl)
* Code Examples
 * [Python](#python)
 * [Ruby](#ruby)
 * [PHP](#php)
 * [Perl](#perl)
 * [Go](#go)
 * [C#](#c)

#### VCL

The code that enables token auth should be placed in `vcl_recv`. This is an example:

```vcl
/* only do this once per request */
if (req.restarts == 0) {
  declare local var.token_exp STRING;
  declare local var.token_sig STRING;

  /* make sure there is a token */
  if (req.url !~ ".+\?.*token=(\d{10,11})_([^&]+)") {
    error 403;
  }

  /* extract token expiration and signature */
  set var.token_exp = re.group.1;
  set var.token_sig = re.group.2;

  /* validate signature */
  if (var.token_sig == regsub(digest.hmac_sha256(digest.base64_decode("YOUR%SECRET%KEY%IN%BASE64%HERE"),
      req.url.path var.token_exp), "^0x", "")) {

    /* check that expiration time has not elapsed */
    if (time.is_after(now, std.integer2time(std.atoi(var.token_exp)))) {
      error 410;
    }
  } else {
    error 403;
  }
}
```

> NOTE: Please generate your own key before using this code. The example key will intentionally cause an error if you use it. Also, due to limitations in VCL, the binary form of the key should not contain any NUL (0x00) bytes. Please generate a new key with one of the following commandlines:
> Linux: `while (b=`openssl rand -base64 32` ; echo $b; echo $b | base64 -d | hd | grep " 00 " > /dev/null); do :; done | tail -1`
> OSX: `while (b=`openssl rand -base64 32` ; echo $b; echo $b | base64 -D | hexdump | grep " 00 " > /dev/null); do :; done | tail -1`

This code expects to find a token in the `?token=` GET parameter. Tokens take the format of `[expiration]_[signature]` and look like this: `1533249205_12f5b21620c2ceae16233f3b9504d6fbf42e9aad8503ed95be0bfb5f96cf3828`. The full request URL would look like this: 

`http://www.example.com/foo/bar.html?token=1533249205_12f5b21620c2ceae16233f3b9504d6fbf42e9aad8503ed95be0bfb5f96cf3828`.

The key used in `digest.hmac_sha256` can be any string, but it is recommended to use base64 encoded random data as described in the note above.

The VCL checks for two things:

 1. Is the current time greater than the expiration time specified in the token?
 2. Does our signature match the signature of the token?

If the signature is invalid, Varnish will return a 403. If the signature is valid but the expiration time has elapsed, Varnish will return a 410. The different response codes are helpful for debugging (and also "more correct"). It is not possible for a malicious user to modify the expiration time of their token--if they did the signature would no longer match. 

#### Client Side Scripts

The client or web application will need to be able to generate tokens to authenticate with Varnish. 

##### Python

```python
import hmac
from hashlib import sha256
import time
import base64

key = base64.b64decode("YOUR%SECRET%KEY%IN%BASE64%HERE")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = int(time.time()) + token_lifetime

string_to_sign = "{0}{1}".format(path,expiration)

digest = hmac.new(key, string_to_sign, sha256)

signature = digest.hexdigest() 

token = "{0}_{1}".format(expiration, signature)

print "Token:   " + token
```

##### Ruby

```ruby
require 'base64'
require 'openssl' 

key = Base64.decode64("YOUR%SECRET%KEY%IN%BASE64%HERE")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = Time.now.to_i + token_lifetime

string_to_sign = path+expiration.to_s

signature = OpenSSL::HMAC.hexdigest('sha256', key, string_to_sign)

token = expiration.to_s + "_" + signature

puts "Token:   " + token
```

##### PHP

```php
<?php
$key = base64_decode("YOUR%SECRET%KEY%IN%BASE64%HERE");
 
$token_lifetime = 1209600; # 2 weeks

$path = "/foo/bar.html";

$expiration = time() + $token_lifetime;

$string_to_sign = $path . $expiration;

$signature = hash_hmac('sha256', $string_to_sign, $key);

$token = $expiration . "_" . $signature;

print("Token:   " . $token . "\n");
?>
```

##### Perl

```perl
use MIME::Base64 'decode_base64';
use Digest::SHA 'hmac_sha256_hex';

my $key = decode_base64("YOUR%SECRET%KEY%IN%BASE64%HERE");

my $token_lifetime = 1209600; # 2 weeks

my $path = "/foo/bar.html";

my $expiration = time() + $token_lifetime;

my $string_to_sign = $path . $expiration;

my $signature = hmac_sha256_hex($string_to_sign, $key);

my $token = "${expiration}_${signature}";

print "Token:   $token\n";
```

##### Go

```go
// this example can be modified and run at https://play.golang.org/p/BYXqllJy_J

package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "encoding/hex"
    "fmt"
    "time"
)

const (
    encodedKey    = "YOUR%SECRET%KEY%IN%BASE64%HERE"
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

    h := hmac.New(sha256.New, key)
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

namespace FastlyToken
{
  class Token
  {
    static void Main(string[] args)
    {
      byte[] key = Convert.FromBase64String("YOUR%SECRET%KEY%IN%BASE64%HERE");

      Int32 lifetime = 1209600;

      string path = "/foo/bar.html";

      Int32 expiration = (Int32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;

      expiration += lifetime;

      string string_to_sign = path + expiration.ToString();

      var encoding = new System.Text.UTF8Encoding();
      byte[] messageBytes = encoding.GetBytes(string_to_sign);
      using (var hmacsha256 = new HMACSHA256(key))
      {
        byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
        Console.WriteLine(expiration + "_" + BitConverter.ToString(hashmessage).Replace("-", string.Empty).ToLower());
      }
    }
  }
}
```
