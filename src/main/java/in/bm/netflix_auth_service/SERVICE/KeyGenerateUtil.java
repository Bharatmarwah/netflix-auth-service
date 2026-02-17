package in.bm.netflix_auth_service.SERVICE;

import java.security.KeyPairGenerator;
import java.util.Base64;

public class KeyGenerateUtil {
    public static void main(String[] args) throws Exception{
        KeyPairGenerator genertor = KeyPairGenerator.getInstance("RSA");
        genertor.initialize(2048);
        var pair = genertor.generateKeyPair();

        String privateKey = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        String publicKey = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());


        System.out.println("Private Key: " + privateKey);
        System.out.println("Public Key: " + publicKey);
    }
}
