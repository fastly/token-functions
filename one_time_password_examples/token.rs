#[macro_use]
extern crate structure;

use std::time::{SystemTime};
use sha2::Sha256;
use hmac::{Hmac, Mac};


fn main() {
    type HmacSha256 = Hmac<Sha256>;

    let encodedkey = "RmFzdGx5IFRva2VuIFRlc3Q=";
    let interval = 60;

    let key = base64::decode(encodedkey).unwrap();
    let numstrct = structure::structure!("<Q");
    let number = numstrct.pack(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() / interval).unwrap();
    
    let mut hmac = HmacSha256::new_varkey(&key).unwrap();
    hmac.input(&number);
    let result = base64::encode(hmac.result().code());

    println!("Your token: {}", result);
    println!("Fastly token: {}", ureq::get("http://token.fastly.com/token").call().into_string().unwrap());
    println!("Validation: {}", ureq::get(&format!("http://token.fastly.com?{}", result)).call().into_string().unwrap());
}

