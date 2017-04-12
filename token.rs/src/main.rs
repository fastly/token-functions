extern crate "rustc-serialize" as serialize;
extern crate openssl;
extern crate http;
extern crate url;
extern crate time;

use std::io::extensions::u64_to_le_bytes;
use http::client::RequestWriter;
use http::method::Get;
use url::Url;

use serialize::base64::{ToBase64, FromBase64, STANDARD};
use openssl::crypto::hash::HashType::SHA256;
use openssl::crypto::hmac::HMAC;

fn main() {
    let encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q=";
    let interval: u64 = 60;

    let key  = encodedkey.from_base64();
    let time = time::now_utc().to_timespec();
    let number =  time.sec as u64 / interval;  // time::precise_time_ns() as u64;

    let mut digest = HMAC(SHA256, key.unwrap().as_slice());
    u64_to_le_bytes(number, 8, |raw| digest.update(raw));

    let token = digest.finalize().to_base64(STANDARD);
    let response   = get_url("http://token.fastly.com/token");
    let validation = get_url(("http://token.fastly.com?".to_string() + token.as_slice()).as_slice());

    println!("Your Token:   {}", token);
    println!("Fastly Token: {}", response);
    println!("Validation:   {}", validation);
}

fn get_url(url: &str) -> String {
    let uri = Url::parse(url).unwrap();
    let request: RequestWriter = RequestWriter::new(Get, uri).unwrap();
    let mut response = request.read_response().ok().expect("Failed to send request");
    let response_text: String = response.read_to_string().ok().expect("Failed to read response");

    return response_text;
}