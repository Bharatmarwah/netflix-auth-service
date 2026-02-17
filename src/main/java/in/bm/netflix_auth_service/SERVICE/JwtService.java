package in.bm.netflix_auth_service.SERVICE;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;


import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;


@Service
public class JwtService {

    private static final String ISSUER = "NETFLIX_auth_service";
    private static final long Access_Token_Validity = 60 * 3 * 1000L;
    private static final long Refresh_Token_Validity = 30L * 24 * 60 * 60 * 1000;

    @Value("${jwt.private.key}")
    private String privateKey;


    public String generateAccessToken(String userId, String role) {
        return Jwts
                .builder()
                .issuer(ISSUER)
                .claim("role", role)
                .claim("type", "ACCESS")
                .subject(userId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + Access_Token_Validity))
                .signWith(getPrivateKey())
                .compact();
    }

    public String generateRefreshToken(String userId, String role) {
        return Jwts
                .builder()
                .issuer(ISSUER)
                .claim("role", role)
                .claim("type", "REFRESH")
                .subject(userId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + Refresh_Token_Validity))
                .signWith(getPrivateKey())
                .compact();
    }

    private PrivateKey getPrivateKey() {
        try {
            byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    public String getRefreshTokenHash(String refreshToken) {

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(refreshToken.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash refresh token", e);
        }


    }
}
