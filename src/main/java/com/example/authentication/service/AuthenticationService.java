package com.example.authentication.service;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.authentication.config.JwtService;
import com.example.authentication.controller.AuthenticationResponse;
import com.example.authentication.controller.ResgisterRequest;
import com.example.authentication.model.Role;
import com.example.authentication.model.User;
import com.example.authentication.repository.UserRepository;

@Service
public class AuthenticationService {
    
    private UserRepository userRepository;

    private PasswordEncoder passwordEncoder;

    public AuthenticationService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }
    public AuthenticationService() {
    }


    public AuthenticationService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    private JwtService jwtService;
    public AuthenticationResponse registerService(ResgisterRequest request){
        var user = User.builder()
            .firstname(request.getFirstname())
            .lastname(request.getLastname())
            .username(request.getUsername())
            .email(request.getEmail())
            .password(passwordEncoder.encode(request.getPassword()))
            .role(Role.USER)
            .build();
        
        userRepository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
            .token(jwtToken)
            .build();
    }

}
