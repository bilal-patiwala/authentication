package com.example.authentication.service;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.example.authentication.config.JwtService;
import com.example.authentication.controller.AuthenticationRequest;
import com.example.authentication.controller.AuthenticationResponse;
import com.example.authentication.controller.ResgisterRequest;
import com.example.authentication.model.Role;
import com.example.authentication.model.User;
import com.example.authentication.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;


    private final AuthenticationManager authenticationManager;
    
    private final JwtService jwtService;
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

    public AuthenticationResponse authenticate(AuthenticationRequest request){
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        var user = userRepository.findByUsername(request.getUsername());

        var jwtToken = jwtService.generateToken(user.get());

        return AuthenticationResponse.builder().token(jwtToken).build();

    }

}
