package com.hjusic.auth.domain.auth.api;

import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.auth.api.dto.TokenResponse;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.service.JwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerTest {

  @Test
  @DisplayName("login authenticates and returns TokenResponse built from JwtService")
  void loginSuccess() {
    // Arrange
    AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    JwtService jwtService = mock(JwtService.class);
    Users users = mock(Users.class);
    AuthController controller = new AuthController(authenticationManager, users, jwtService);

    LoginRequest req = new LoginRequest();
    req.setUsername("alice");
    req.setPassword("secret");

    UserDetails principal = new User("alice", "secret",
        List.of(new SimpleGrantedAuthority("ROLE_USER")));

    Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(auth);

    when(jwtService.generateToken(principal)).thenReturn("access.jwt.token");
    when(jwtService.generateRefreshToken(principal)).thenReturn("refresh.jwt.token");
    when(jwtService.getExpirationTime()).thenReturn(3600000L);
    when(jwtService.getRefreshExpirationTime()).thenReturn(604800000L);

    // Act
    ResponseEntity<TokenResponse> response = controller.login(req);

    // Assert
    assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    TokenResponse body = response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getType()).isEqualTo("Bearer");
    assertThat(body.getToken()).isEqualTo("access.jwt.token");
    assertThat(body.getRefreshToken()).isEqualTo("refresh.jwt.token");
    assertThat(body.getExpiresIn()).isEqualTo(3600000L);
    assertThat(body.getRefreshExpiresIn()).isEqualTo(604800000L);
  }
}
