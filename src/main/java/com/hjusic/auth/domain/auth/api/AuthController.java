package com.hjusic.auth.domain.auth.api;

import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.auth.api.dto.TokenResponse;
import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.service.JwtService;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

  private final AuthenticationManager authenticationManager;
  private final Users users;
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

  @GetMapping("/verify")
  public ResponseEntity<?> verifyToken(@RequestHeader("Authorization") String authHeader) {
    try {
      String token = authHeader.replace("Bearer ", "");
      String username = jwtService.extractUsername(token);

      var user = users.findByUsername(username);

      if(user.isLeft()) {
        return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
      }

      // Determine Grafana role based on your roles
      String grafanaRole = determineGrafanaRole(user.get().getRoles());

      var roleNames = user.get().getRoles().stream()
          .map(role -> role.getName().toString())
          .collect(Collectors.toList());

      return ResponseEntity.ok(Map.of(
          "sub", username,
          "login", username,
          "email", user.get().getEmail().getValue(),
          "name", username,
          "role", grafanaRole,
          "groups", roleNames
      ));
    } catch (Exception e) {
      return ResponseEntity.status(401).body(Map.of("error", "Invalid token"));
    }
  }

  private String determineGrafanaRole(Set<Role> roles) {
    var roleNames = roles.stream()
        .map(role -> role.getName().toString())
        .collect(Collectors.toSet());

    if (roleNames.contains("ROLE_ADMIN")) {
      return "Admin";
    } else if (roleNames.contains("ROLE_EDITOR")) {
      return "Editor";
    } else {
      return "Viewer";
    }
  }


}
