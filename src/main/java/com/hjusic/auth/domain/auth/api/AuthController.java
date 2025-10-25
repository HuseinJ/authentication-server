package com.hjusic.auth.domain.auth.api;

import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.auth.api.dto.TokenResponse;
import com.hjusic.auth.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;

  @PostMapping("/login")
  public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
    );

    UserDetails user = (UserDetails) authentication.getPrincipal();
    String token = jwtService.generateToken(user);
    String refreshToken = jwtService.generateRefreshToken(user);

    return ResponseEntity.ok(new TokenResponse(token, refreshToken, jwtService.getExpirationTime(),
        jwtService.getRefreshExpirationTime()));
  }

}
