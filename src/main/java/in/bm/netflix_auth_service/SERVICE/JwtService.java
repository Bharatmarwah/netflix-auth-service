package in.bm.netflix_auth_service.SERVICE;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;

@Service
public class JwtService {

    private static final String ISSUER = "NETFLIX_auth_service";
    private static final long Access_Token_Validity = 60 * 3 * 1000L;
    private static final long Refresh_Token_Validity = 30L * 24 * 60 * 60 * 1000;

    @Value("${jwt.secret.key}")
    private String secretKey;


    public String generateAccessToken(String userId, String role) {
        return Jwts
                .builder()
                .issuer(ISSUER)
                .claim("role", role)
                .claim("type", "ACCESS")
                .subject(userId)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + Access_Token_Validity))
                .signWith(getKey())
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
                .expiration(new Date(System.currentTimeMillis() +Refresh_Token_Validity))
                .signWith(getKey())
                .compact();
    }

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);

    }

}
