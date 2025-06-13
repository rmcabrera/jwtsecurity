package com.auth.jwt.security;

import com.auth.jwt.dto.RequestDto;
import com.auth.jwt.model.AuthUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtProvider {
    private Key secret;
    @Autowired
    private RouteValidator routeValidator;

    @PostConstruct
    protected void init() {
        byte[] apiKeySecretBytes = new byte[64] ;
        new SecureRandom().nextBytes(apiKeySecretBytes);
        secret = Keys.hmacShaKeyFor(apiKeySecretBytes);
    }
    private Date convertToLocalDateTimeToDate(LocalDateTime localDateTime){
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    public String createToken(AuthUser authUser){
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", authUser.getId());
        claims.put("role",authUser.getRole());
        LocalDateTime now = LocalDateTime.now();
        return Jwts.builder()
                .claims(claims)
                .subject(authUser.getUserName())
                .issuedAt(this.convertToLocalDateTimeToDate(now))
                .expiration(this.convertToLocalDateTimeToDate(now.plusHours(12)))
                .signWith(Keys.hmacShaKeyFor(secret.getEncoded()))
                .compact();
    }

    public String getUserNameFromToken(String token) {
        try{
            return Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secret.getEncoded()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload().getSubject();
        } catch (Exception e) {
            return  "Bad token";
        }
    }

    public boolean validate(String token, RequestDto requestDto) {
        try {
            Jwts.parser().verifyWith(
                            Keys.hmacShaKeyFor(secret.getEncoded())
                    )
                    .build()
                    .parseClaimsJws(token);

        } catch (Exception e) {
            return false;
        }
        if(!isAdmin(token) && routeValidator.isAdmin(requestDto)){
            return false;
        }
        return true;
    }
    public boolean isAdmin(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(Keys.hmacShaKeyFor(secret.getEncoded()))
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            String role = (String) claims.get("role");
            return "ADMIN".equalsIgnoreCase(role); // o simplemente "ADMIN".equals(role)
        } catch (Exception e) {
            return false;
        }
    }


}
