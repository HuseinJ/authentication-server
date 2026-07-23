package com.hjusic.auth.jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

/**
 * Issues signed access/refresh tokens using Spring Security's {@link JwtEncoder} (Nimbus) over the
 * application's configured {@code JWKSource}. Replaces the previous hand-rolled jjwt implementation;
 * tokens are RS256-signed with the same key the OAuth2 Authorization Server and resource servers use,
 * so a token minted here validates through the standard {@code JwtDecoder}.
 */
@Service
@RequiredArgsConstructor
public class TokenIssuer {

  private final JwtEncoder jwtEncoder;

  @Value("${jwt.expiration}")
  private long accessTokenTtlMillis;

  @Value("${jwt.refresh-expiration}")
  private long refreshTokenTtlMillis;

  @Value("${jwt.issuer}")
  private String issuer;

  public String generateToken(UserDetails userDetails) {
    return buildToken(userDetails, accessTokenTtlMillis);
  }

  public String generateRefreshToken(UserDetails userDetails) {
    return buildToken(userDetails, refreshTokenTtlMillis);
  }

  public long getExpirationTime() {
    return accessTokenTtlMillis;
  }

  public long getRefreshExpirationTime() {
    return refreshTokenTtlMillis;
  }

  private String buildToken(UserDetails userDetails, long ttlMillis) {
    Instant now = Instant.now();
    List<String> roles = userDetails.getAuthorities().stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList());

    JwtClaimsSet claims = JwtClaimsSet.builder()
        .issuer(issuer)
        .subject(userDetails.getUsername())
        .issuedAt(now)
        .expiresAt(now.plus(ttlMillis, ChronoUnit.MILLIS))
        .id(UUID.randomUUID().toString())
        .claim("roles", roles)
        .build();

    return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
  }
}
