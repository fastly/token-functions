<?

function pack64($value) {
  $l = ($value & 0xffffffff00000000) >>32;
  $r = $value & 0x00000000ffffffff;

  return pack('VV', $r, $l); 
}

function curl_get_contents($url)
{
  $ch = curl_init();
  curl_setopt($ch, CURLOPT_URL, $url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
  curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
  $data = curl_exec($ch);
  curl_close($ch);
  return $data;
}

$encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q=";
$interval = 60;
 
$key = base64_decode($encodedkey);
 
$number = pack64(intval(time()/$interval));
$token  = base64_encode(hash_hmac('sha256', $number, $key, true));

$response   = curl_get_contents("http://token.fastly.com/token");
$validation = curl_get_contents("http://token.fastly.com?$token");

print "Your Token:   $token\n";
print "Fastly Token: $response\n";
print "Validation:   $validation\n";

?>