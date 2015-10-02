use strict;
use warnings;

use LWP::Simple;
use MIME::Base64;
use Digest::SHA qw(hmac_sha256);

my $encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q=";
my $interval = 60;
 
my $key = decode_base64($encodedkey);
 
my $number = pack "Q<", time/$interval;
my $token  = encode_base64(hmac_sha256($number, $key),'');
 
my $response   = get("http://token.fastly.com/token");
my $validation = get("http://token.fastly.com?$token");
 
print "Your Token:   $token\n";
print "Fastly Token: $response\n";
print "Validation:   $validation\n";
