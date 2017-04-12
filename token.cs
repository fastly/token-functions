using System;
using System.Net;
using System.Security.Cryptography;

namespace FastlyTokenVerifier
{
    class Token
    {
        static void Main(string[] args)
        {
            var encodedKey = "RmFzdGx5IFRva2VuIFRlc3Q=";
            var interval = 60;


            var token = CreateToken(interval, encodedKey);
            string response;
            string validation;
            using (var client = new WebClient())
            {
                response = client.DownloadString("http://token.fastly.com/token");
                validation = client.DownloadString("http://token.fastly.com?" + token);
            }

            Console.WriteLine("Your Token:   " + token);
            Console.WriteLine("Fastly Token: " + response);
            Console.WriteLine("Validation:   " + validation);
        }

        static string CreateToken(int interval, string base64EncodedKey)
        {
            var number = ((long)(DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalSeconds) / interval;
            byte[] key = Convert.FromBase64String(base64EncodedKey);
            byte[] data = BitConverter.GetBytes(number);
            using (var hmacsha256 = new HMACSHA256(key))
            {
                byte[] hmac = hmacsha256.ComputeHash(data);
                return Convert.ToBase64String(hmac);
            }
        }
    }
}
