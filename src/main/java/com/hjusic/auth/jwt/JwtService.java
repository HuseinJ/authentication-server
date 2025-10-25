package com.hjusic.auth.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Service
public class JwtService {

  @Value("${jwt.private-key}")
  private String privateKeyString;

  @Value("${jwt.public-key}")
  private String publicKeyString;

  @Value("${jwt.expiration}")
  private long jwtExpiration;

  @Value("${jwt.refresh-expiration}")
  private long refreshExpiration;

  @Value("${jwt.issuer}")
  private String issuer;

  /**
   * Extract username from JWT token
   */
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  /**
   * Extract a specific claim from the token
   */
  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  /**
   * Generate access token for user
   */
  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  /**
   * Generate access token with extra claims
   */
  public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
    return buildToken(extraClaims, userDetails, jwtExpiration);
  }

  /**
   * Generate refresh token
   */
  public String generateRefreshToken(UserDetails userDetails) {
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  /**
   * Build JWT token using RSA private key
   */
  private String buildToken(
      Map<String, Object> extraClaims,
      UserDetails userDetails,
      long expiration
  ) {
    var roles = userDetails.getAuthorities()
        .stream()
        .map(GrantedAuthority::getAuthority)
        .collect(Collectors.toList());

    Instant now = Instant.now();

    return Jwts.builder()
        .claims(extraClaims)
        .subject(userDetails.getUsername())
        .claim("roles", roles)
        .id(java.util.UUID.randomUUID().toString())
        .issuer(issuer)
        .issuedAt(Date.from(now))
        .expiration(Date.from(now.plus(expiration, ChronoUnit.MILLIS)))
        .signWith(getPrivateKey())
        .compact();
  }

  /**
   * Validate token against user details
   */
  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  /**
   * Check if token is expired
   */
  private boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  /**
   * Extract expiration date from token
   */
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  /**
   * Extract all claims from token using PUBLIC key
   */
  private Claims extractAllClaims(String token) {
    return Jwts.parser()
        .verifyWith(getPublicKey())  // Verify with PUBLIC key
        .build()
        .parseSignedClaims(token)
        .getPayload();
  }

  /**
   * Load RSA private key for signing
   */
  private PrivateKey getPrivateKey() {
    try {
      String privateKeyPEM = privateKeyString
          .replace("-----BEGIN PRIVATE KEY-----", "")
          .replace("-----END PRIVATE KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(privateKeyPEM);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePrivate(keySpec);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load private key", e);
    }
  }

  /**
   * Load RSA public key for verification
   */
  private PublicKey getPublicKey() {
    try {
      String publicKeyPEM = publicKeyString
          .replace("-----BEGIN PUBLIC KEY-----", "")
          .replace("-----END PUBLIC KEY-----", "")
          .replaceAll("\\s", "");

      byte[] decoded = Base64.getDecoder().decode(publicKeyPEM);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      return keyFactory.generatePublic(keySpec);
    } catch (Exception e) {
      throw new RuntimeException("Failed to load public key", e);
    }
  }

  /**
   * Extract roles from token
   */
  @SuppressWarnings("unchecked")
  public java.util.List<String> extractRoles(String token) {
    Claims claims = extractAllClaims(token);
    return claims.get("roles", java.util.List.class);
  }

  /**
   * Get token expiration time in milliseconds
   */
  public long getExpirationTime() {
    return jwtExpiration;
  }

  /**
   * Get refresh token expiration time in milliseconds
   */
  public long getRefreshExpirationTime() {
    return refreshExpiration;
  }

  /**
   * Get public key as string (for sharing with other services)
   */
  public String getPublicKeyString() {
    return publicKeyString;
  }
}