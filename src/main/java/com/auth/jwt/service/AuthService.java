package com.auth.jwt.service;

import com.auth.jwt.dto.AuthUserDto;
import com.auth.jwt.dto.NewUserDto;
import com.auth.jwt.dto.TokenDto;
import com.auth.jwt.model.AuthUser;
import com.auth.jwt.repository.AuthUserRepository;
import com.auth.jwt.security.JwtProvider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService implements UserDetailsService {

    @Autowired
    private AuthUserRepository authUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtProvider jwtProvider;

    public AuthUser save(NewUserDto dto){
        Optional<AuthUser> user = authUserRepository.findByUserName(dto.getUserName());
        if(user.isPresent()){
            return null; 
        }

        String password = passwordEncoder.encode(dto.getPassword());
        AuthUser authUser = AuthUser.builder()
                .userName(dto.getUserName())
                .password(password)
                .role(dto.getRole())
                .build();
        return authUserRepository.save(authUser);
    }

    public TokenDto login(AuthUserDto dto){
        Optional<AuthUser> user = authUserRepository.findByUserName(dto.getUserName());
        if(user.isEmpty()){
            return null;
        }
        if(passwordEncoder.matches(dto.getPassword(), user.get().getPassword())){
            return new TokenDto(jwtProvider.createToken(user.get()));
        }
        return null; 
    }

    public TokenDto validate(String token) {
        if (jwtProvider.validate(token)) {
            return new TokenDto(token);
        }
        return null;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        AuthUser authUser = authUserRepository.findByUserName(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));
        return org.springframework.security.core.userdetails.User.builder()
                .username(authUser.getUserName())
                .password(authUser.getPassword())
                .roles(authUser.getRole())
                .build();
    }
}
