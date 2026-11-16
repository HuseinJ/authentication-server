package com.hjusic.auth.domain.auth.api;

import com.hjusic.auth.domain.auth.api.dto.LoginRequest;
import com.hjusic.auth.domain.auth.api.dto.MfaChallengeResponse;
import com.hjusic.auth.domain.auth.api.dto.MfaLoginRequest;
import com.hjusic.auth.domain.auth.api.dto.TokenResponse;
import com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthenticator;
import com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthorities;
import com.hjusic.auth.domain.mfa.infrastructure.security.SecondFactorAuthorizationManager;
import com.hjusic.auth.domain.mfa.infrastructure.security.TotpAuthenticationToken;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.jwt.TokenIssuer;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.FactorAuthorizationDecision;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtDecoder;
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
  private final TokenIssuer tokenIssuer;
  private final JwtDecoder jwtDecoder;
  private final SecondFactorAuthorizationManager secondFactorAuthorizationManager;
  private final SecondFactorAuthenticator secondFactorAuthenticator;
  private final OneTimeTokenService oneTimeTokenService;

  @Value("${auth.mfa.challenge-ttl:PT5M}")
  private Duration mfaChallengeTtl;

  /**
   * Password login. Users with a second factor enrolled get an {@link MfaChallengeResponse}
   * instead of tokens and finish via {@link #loginWithTotp}.
   */
  @PostMapping("/login")
  public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
    Authentication authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
    );

    // Same policy as /oauth2/authorize: password, plus one enrolled second factor if any.
    AuthorizationResult decision = secondFactorAuthorizationManager.authorize(
        () -> authentication, null);
    if (decision.isGranted()) {
      return ResponseEntity.ok(issueTokens((UserDetails) authentication.getPrincipal()));
    }

    return ResponseEntity.ok(createChallenge(authentication.getName(), missingFactors(decision)));
  }

  /** Second step of a password login for users with TOTP enabled. */
  @PostMapping("/login/mfa/totp")
  public ResponseEntity<?> loginWithTotp(@RequestBody MfaLoginRequest request) {
    OneTimeToken challenge = request.getMfaToken() == null
        ? null
        : oneTimeTokenService.consume(new OneTimeTokenAuthenticationToken(request.getMfaToken()));
    if (challenge == null) {
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
          .body(Map.of("error", "MFA challenge is invalid or expired; log in again"));
    }

    try {
      Authentication authentication = secondFactorAuthenticator.authenticate(
          TotpAuthenticationToken.unauthenticated(challenge.getUsername(),
              request.getCode() == null ? "" : request.getCode()));
      return ResponseEntity.ok(issueTokens((UserDetails) authentication.getPrincipal()));
    } catch (LockedException e) {
      return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
          .body(Map.of("error", "Too many invalid codes; try again later"));
    } catch (AuthenticationException e) {
      // The challenge is single-use; hand out a fresh one so a typo doesn't force a new password
      // entry. Guessing is bounded by the lockout in the TOTP credential.
      var retry = createChallenge(challenge.getUsername(), List.of(SecondFactorType.TOTP.getId()));
      return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
          "error", "Invalid verification code",
          "mfaToken", retry.mfaToken(),
          "expiresIn", retry.expiresIn()));
    }
  }

  private TokenResponse issueTokens(UserDetails user) {
    return new TokenResponse(tokenIssuer.generateToken(user), tokenIssuer.generateRefreshToken(user),
        tokenIssuer.getExpirationTime(), tokenIssuer.getRefreshExpirationTime());
  }

  private MfaChallengeResponse createChallenge(String username, List<String> factors) {
    OneTimeToken token = oneTimeTokenService.generate(
        new GenerateOneTimeTokenRequest(username, mfaChallengeTtl));
    return MfaChallengeResponse.of(token.getTokenValue(), factors, mfaChallengeTtl.toSeconds());
  }

  private static List<String> missingFactors(AuthorizationResult decision) {
    if (!(decision instanceof FactorAuthorizationDecision factorDecision)) {
      return List.of();
    }
    return factorDecision.getFactorErrors().stream()
        .map(error -> error.getRequiredFactor().getAuthority())
        .map(SecondFactorAuthorities::typeOf)
        .flatMap(Optional::stream)
        .map(SecondFactorType::getId)
        .distinct()
        .toList();
  }

  @GetMapping("/verify")
  public ResponseEntity<?> verifyToken(@RequestHeader("Authorization") String authHeader) {
    try {
      String token = authHeader.replace("Bearer ", "");
      String username = jwtDecoder.decode(token).getSubject();

      var user = users.findByUsername(username);

      if (user.isLeft()) {
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
