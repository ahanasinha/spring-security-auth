package com.example.auth.controller;

import com.example.auth.service.SecurityService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SecurityController {

    @Autowired
    private SecurityService securityService;

    @GetMapping("/login")
    public Map<String, String> login(@RequestParam String username, @RequestParam String password, HttpServletRequest request) {
        Map<String, String> result = securityService.loginService(username, password);
        String token = result.get("token");
        if (token != null) {
            request.getSession().setAttribute("JWT_TOKEN", token);
        }
        return result;
    }

    @GetMapping("/status")
    public Map<String, String> status(@RequestHeader("Authorization") String token) {
        return securityService.getStatus(token.replace("Bearer ", ""));
    }

    @GetMapping("/status/admin")
    public Map<String, String> adminStatus(@RequestHeader("Authorization") String token) {
        return securityService.getAdminStatus(token.replace("Bearer ", ""));
    }
}
