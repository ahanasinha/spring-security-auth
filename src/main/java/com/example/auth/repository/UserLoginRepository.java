package com.example.auth.repository;

import com.example.auth.model.UserLogin;
import org.springframework.data.mongodb.repository.MongoRepository;
import java.util.Optional;

public interface UserLoginRepository extends MongoRepository<UserLogin, String> {
    Optional<UserLogin> findByUsername(String username);
}