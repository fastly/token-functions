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