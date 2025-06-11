package com.auth.jwt.security;


import com.auth.jwt.model.AuthUser;
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

    @PostConstruct
    protected void init(){
        byte[] apiKeySecretBytes = new byte[64]; 
        new SecureRandom().nextBytes(apiKeySecretBytes);
        secret = Keys.hmacShaKeyFor(apiKeySecretBytes);
    }

    public String createToken(AuthUser authUser){
        Map<String, Object> claims = new HashMap<>();
        claims.put("id", authUser.getId());
        claims.put("role", authUser.getRole());
        claims.put("company", "AulaMatriz"); 

        LocalDateTime now = LocalDateTime.now();

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(authUser.getUserName())
                .setIssuedAt(convertToLocalDateTimeToDate(now))
                .setExpiration(convertToLocalDateTimeToDate(now.plusHours(12))) // 12 hours as seen in image
                .signWith(secret) 
                .compact();
    }

    private Date convertToLocalDateTimeToDate(LocalDateTime localDateTime) {
        return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
    }

    public String getUsernameFromToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(secret)
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validate(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(secret)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
