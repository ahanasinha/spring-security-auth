package com.example.auth.service;

import com.example.auth.model.UserLogin;
import com.example.auth.repository.UserLoginRepository;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.*;
import java.nio.charset.StandardCharsets;

@Service
public class SecurityService {

    @Autowired
    private UserLoginRepository userRepository;

    private static final long EXPIRATION_TIME = 90000; // 1.5 minute in milliseconds
    private static final SecretKey SECRET_KEY = Keys.hmacShaKeyFor("securesecuresecuresecuresecuresecuresecuresecure".getBytes(StandardCharsets.UTF_8));

    public static SecretKey getSecretKey() {
        return SECRET_KEY;
    }

    public String generateJwtToken(String username, String password) {
        if (validateUser(username, password)) {
            UserLogin user = userRepository.findByUsername(username).orElseThrow();
            String role = user.getRole();

            return Jwts.builder()
                    .setSubject(username)
                    .claim("role", role)
                    .setIssuedAt(Date.from(Instant.now()))
                    .setExpiration(Date.from(Instant.now().plusMillis(EXPIRATION_TIME)))
                    .signWith(SECRET_KEY, SignatureAlgorithm.HS256)
                    .compact();
        }
        return null;
    }

    private boolean validateUser(String username, String password) {
        Optional<UserLogin> userOptional = userRepository.findByUsername(username);

        if (userOptional.isPresent()) {
            return userOptional
                    .get()
                    .getPassword()
                    .equals(password);
        }
        return false;
    }

    public Map<String, String> loginService(String username, String password) {
        String token = generateJwtToken(username, password);
        Map<String, String> response = new HashMap<>();
        if (token != null) {
            response.put("token", token);
        } else {
            response.put("error", "Invalid username or password");
        }
        return response;
    }

    public Map<String, String> getStatus(String token) {
        Map<String, String> response = new HashMap<>();
        try {
            String username=Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();

            Optional<UserLogin> userOptional = userRepository.findByUsername(username);

            if (userOptional.isPresent()) {
                UserLogin user = userOptional.get();
                response.put("role", user.getRole());
                response.put("App status","App is running successfully");
            } else {
                response.put("error", "User not found");
            }
        } catch (Exception e) {
            response.put("error", "Token mismatch");
        }
        return response;
    }

    public Map<String, String> getAdminStatus(String token) {
        Map<String, String> AdminResponse = new HashMap<>();
        try {
            String username=Jwts.parserBuilder()
                    .setSigningKey(SECRET_KEY)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();

            Optional<UserLogin> userOptional = userRepository.findByUsername(username);

            if (userOptional.isPresent()) {
                UserLogin user = userOptional.get();
                if(user.getRole().equalsIgnoreCase("admin")){
                    AdminResponse.put("role","Admin");
                    AdminResponse.put("App status","App is running successfully");
                }else{
                    AdminResponse.put("role","Invalid User");
                }
            } else {
                AdminResponse.put("error", "User not found");
            }
        } catch (Exception e) {
            AdminResponse.put("error", "Token mismatch");
        }
        return AdminResponse;
    }
}