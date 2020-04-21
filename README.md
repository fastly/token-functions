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
 * [Java](#java)

#### VCL

The VCL code that enables token authentication is described in [Enabling
URL token
validation](https://docs.fastly.com/guides/tutorials/enabling-url-token-validation).

#### Client Side Scripts

The client or web application will need to be able to generate tokens to authenticate with Varnish. 

##### Python

```python
import hmac
from hashlib import sha1
import time
import base64

key = base64.b64decode("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = int(time.time()) + token_lifetime

string_to_sign = "{0}{1}".format(path,expiration)

digest = hmac.new(key, string_to_sign, sha1)

signature = digest.hexdigest() 

token = "{0}_{1}".format(expiration, signature)

print "Token:   " + token
```

##### Ruby

```ruby
require 'base64'
require 'openssl' 

key = Base64.decode64("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=")

token_lifetime = 1209600 # 2 weeks

path = "/foo/bar.html"

expiration = Time.now.to_i + token_lifetime

string_to_sign = path+expiration.to_s

signature = OpenSSL::HMAC.hexdigest('sha1', key, string_to_sign)

token = expiration.to_s + "_" + signature

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

$token = $expiration . "_" . $signature;

print("Token:   " . $token . "\n");
?>
```

##### Perl

```perl
use MIME::Base64 'decode_base64';
use Digest::SHA 'hmac_sha1_hex';

my $key = decode_base64("iqFPeN2u+Z0Lm5IrsKaOFKRqEU5Gw8ePtaEkHZWuD24=");

my $token_lifetime = 1209600; # 2 weeks

my $path = "/foo/bar.html";

my $expiration = time() + $token_lifetime;

my $string_to_sign = $path . $expiration;

my $signature = hmac_sha1_hex($string_to_sign, $key);

my $token = "${expiration}_${signature}";

print "Token:   $token\n";
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

##### Java

```
/***
 *
 * Compile with:
 * javac token.java
 *
 * Run with:
 * java token
 * 
 ***/

import java.security.SignatureException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;




public class token {
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";

    public static void main(String[] args) throws Exception {
        String encodedKey = "RmFzdGx5IFRva2VuIFRlc3Q=";
        int    interval   = 60;

        String token;
        try {

            byte[] key  = new sun.misc.BASE64Decoder().decodeBuffer(encodedKey);
            long number  = System.currentTimeMillis()/(interval*1000);
            byte [] data = unpack64(number);

            SecretKeySpec signingKey = new SecretKeySpec(key, HMAC_SHA256_ALGORITHM);

            Mac mac = Mac.getInstance(HMAC_SHA256_ALGORITHM);
            mac.init(signingKey);

            byte[] rawHmac = mac.doFinal(data);
            token = new BASE64Encoder().encode(rawHmac);

        } catch (Exception e) {
            throw new SignatureException("Failed to generate HMAC : " + e.getMessage());
        }

        String response   = getUrl("http://token.fastly.com/token");
        String validation = getUrl("http://token.fastly.com?"+token);

        System.out.println("Your Token:   "+token);
        System.out.println("Fastly Token: "+response);
        System.out.println("Validation:   "+validation);
        
       }
       
       public static byte[] unpack64(long number) {
           ByteBuffer bb = ByteBuffer.allocate(8);
           bb.order(ByteOrder.LITTLE_ENDIAN);
           bb.putLong(number);
           return bb.array();
       }

       public static String getUrl(String urlStr) throws Exception {
           URL url = new URL(urlStr);
           HttpURLConnection connection = null;
           BufferedReader reader = null;
           InputStream is = null;

           try {
               connection = (HttpURLConnection) url.openConnection();
               is = connection.getInputStream();
           }  catch (IOException io) {
               is = connection.getErrorStream();
           }

           try {
               reader = new BufferedReader(new InputStreamReader(is));
               StringBuilder stringBuilder = new StringBuilder();


               String line = null;
               while ((line = reader.readLine()) != null) {
                   stringBuilder.append(line + "\n");
               }
               stringBuilder.setLength(stringBuilder.length() - 1);
               return stringBuilder.toString();
           } finally {
               if (reader != null)
                   reader.close();
           }

       }


}
```
