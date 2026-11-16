package com.hjusic.auth.domain.auth.api;

import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.auth.api.dto.TokenResponse;
import com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthenticator;
import com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthorizationManager;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.jwt.TokenIssuer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AuthControllerTest {

  @Test
  @DisplayName("login authenticates and returns TokenResponse built from TokenIssuer")
  void loginSuccess() {
    // Arrange
    AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
    TokenIssuer tokenIssuer = mock(TokenIssuer.class);
    Users users = mock(Users.class);
    JwtDecoder jwtDecoder = mock(JwtDecoder.class);
    SecondFactorAuthorizationManager mfaPolicy = mock(SecondFactorAuthorizationManager.class);
    when(mfaPolicy.authorize(any(), any())).thenReturn(new AuthorizationDecision(true));
    AuthController controller = new AuthController(authenticationManager, users, tokenIssuer,
        jwtDecoder, mfaPolicy, mock(SecondFactorAuthenticator.class),
        mock(OneTimeTokenService.class));

    LoginRequest req = new LoginRequest();
    req.setUsername("alice");
    req.setPassword("secret");

    UserDetails principal = new User("alice", "secret",
        List.of(new SimpleGrantedAuthority("ROLE_USER")));

    Authentication auth = new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
        .thenReturn(auth);

    when(tokenIssuer.generateToken(principal)).thenReturn("access.jwt.token");
    when(tokenIssuer.generateRefreshToken(principal)).thenReturn("refresh.jwt.token");
    when(tokenIssuer.getExpirationTime()).thenReturn(3600000L);
    when(tokenIssuer.getRefreshExpirationTime()).thenReturn(604800000L);

    // Act
    ResponseEntity<?> response = controller.login(req);

    // Assert
    assertThat(response.getStatusCode().is2xxSuccessful()).isTrue();
    TokenResponse body = (TokenResponse) response.getBody();
    assertThat(body).isNotNull();
    assertThat(body.getType()).isEqualTo("Bearer");
    assertThat(body.getToken()).isEqualTo("access.jwt.token");
    assertThat(body.getRefreshToken()).isEqualTo("refresh.jwt.token");
    assertThat(body.getExpiresIn()).isEqualTo(3600000L);
    assertThat(body.getRefreshExpiresIn()).isEqualTo(604800000L);
  }
}
