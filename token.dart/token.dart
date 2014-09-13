/// Run pub get && dart token.dart
import 'dart:convert';
import 'package:fixnum/fixnum.dart';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

void main() {
  var encodedKey = "RmFzdGx5IFRva2VuIFRlc3Q=";
  var interval   = 60;
  var time       = new DateTime.now().millisecondsSinceEpoch ~/ 1000;
  
  List<int>  key    = CryptoUtils.base64StringToBytes(encodedKey);
  List<int>  number = new Int64(time ~/ interval).toBytes();
  HMAC       hmac   = new HMAC(new SHA256(), key);
  hmac.add(number);
  String token      = CryptoUtils.bytesToBase64(hmac.close());

  print ("Your Token:   "+token);
  http.read("http://token.fastly.com/token")
    .then((response)    => print ("Fastly Token: "+response));
  http.read("http://token.fastly.com?"+token)
    .then((validation) => print ("Validation:   "+validation));
}


