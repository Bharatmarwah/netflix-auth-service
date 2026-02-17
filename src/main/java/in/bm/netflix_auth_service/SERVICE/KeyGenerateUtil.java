package in.bm.netflix_auth_service.SERVICE;

import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGenerateUtil {
    public static void main(String[] args) throws Exception{
        KeyPairGenerator genertor = KeyPairGenerator.getInstance("RSA");// generate a key using RSA algorithm
        genertor.initialize(2048);// set the key size to 2048 bits ( 1byte = 8 bits so 2048 bits = 256 bytes)

        var pair = genertor.generateKeyPair();

        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());// encoded the keys into String format using base64 encoding scheme

        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());


        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}
