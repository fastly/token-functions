var crypto     = require('crypto');
var http       = require('http-sync');
var jspack     = require('jspack').jspack;


var encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q=";
var interval   = 60;
var key        = new Buffer(encodedkey, 'base64').toString('ascii');
var time       = Math.floor(Date.now()/(interval*1000));
var l          = (time & 0xffffffff00000000) >>32
var r          = (time & 0x00000000ffffffff)
var number     = new Buffer(jspack.Pack("<L<L", [r, l]), 'binary'); // "abab"; // pack "Q<", time/$interval;

var token      = crypto.createHmac('SHA256', key).update(number).digest('base64');
var response   = fetchUrl("/token");
var validation = fetchUrl("/?"+token);
 
console.log("Your Token:   "+token);
console.log("Fastly Token: "+response);
console.log("Validation:   "+validation);

function fetchUrl(path) {
  var request = http.request({
      host: 'token.fastly.com',
      path: path
  });
  var response = request.end();
  return response.body.toString();
}
