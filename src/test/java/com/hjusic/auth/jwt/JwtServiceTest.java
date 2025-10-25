package com.hjusic.auth.jwt;

import com.hjusic.auth.service.JwtService;

import io.jsonwebtoken.security.SignatureException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.ActiveProfiles;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(classes = {JwtService.class})
@ActiveProfiles("jwt")
class JwtServiceTest {

  @Autowired
  private JwtService jwtService;

  private UserDetails userDetails;

  @BeforeEach
  void setUp() {
    userDetails = new User(
        "testuser",
        "password123",
        List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN")
        )
    );
  }

  @Test
  @DisplayName("Should generate valid JWT token")
  void shouldGenerateToken() {
    // When
    String token = jwtService.generateToken(userDetails);

    // Then
    assertThat(token).isNotNull();
    assertThat(token).isNotEmpty();
    assertThat(token.split("\\.")).hasSize(3); // Header.Payload.Signature
  }

  @Test
  @DisplayName("Should extract username from token")
  void shouldExtractUsername() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    String username = jwtService.extractUsername(token);

    // Then
    assertThat(username).isEqualTo("testuser");
  }

  @Test
  @DisplayName("Should extract roles from token")
  void shouldExtractRoles() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    List<String> roles = jwtService.extractRoles(token);

    // Then
    assertThat(roles)
        .isNotNull()
        .hasSize(2)
        .containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN");
  }

  @Test
  @DisplayName("Should validate token successfully")
  void shouldValidateToken() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    boolean isValid = jwtService.isTokenValid(token, userDetails);

    // Then
    assertThat(isValid).isTrue();
  }

  @Test
  @DisplayName("Should invalidate token with wrong user")
  void shouldInvalidateTokenWithWrongUser() {
    // Given
    String token = jwtService.generateToken(userDetails);
    UserDetails differentUser = new User(
        "differentuser",
        "password",
        List.of(new SimpleGrantedAuthority("ROLE_USER"))
    );

    // When
    boolean isValid = jwtService.isTokenValid(token, differentUser);

    // Then
    assertThat(isValid).isFalse();
  }

  @Test
  @DisplayName("Should generate refresh token")
  void shouldGenerateRefreshToken() {
    // When
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    // Then
    assertThat(refreshToken).isNotNull();
    assertThat(refreshToken).isNotEmpty();

    String username = jwtService.extractUsername(refreshToken);
    assertThat(username).isEqualTo("testuser");
  }

  @Test
  @DisplayName("Should generate token with extra claims")
  void shouldGenerateTokenWithExtraClaims() {
    // Given
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("userId", 12345);
    extraClaims.put("email", "test@example.com");
    extraClaims.put("department", "Engineering");

    // When
    String token = jwtService.generateToken(extraClaims, userDetails);

    // Then
    assertThat(token).isNotNull();

    String username = jwtService.extractUsername(token);
    assertThat(username).isEqualTo("testuser");

    Integer userId = jwtService.extractClaim(token, claims -> claims.get("userId", Integer.class));
    assertThat(userId).isEqualTo(12345);

    String email = jwtService.extractClaim(token, claims -> claims.get("email", String.class));
    assertThat(email).isEqualTo("test@example.com");

    String department = jwtService.extractClaim(token,
        claims -> claims.get("department", String.class));
    assertThat(department).isEqualTo("Engineering");
  }

  @Test
  @DisplayName("Should extract expiration date from token")
  void shouldExtractExpirationDate() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    Date expiration = jwtService.extractClaim(token, claims -> claims.getExpiration());

    // Then
    assertThat(expiration).isNotNull();
    assertThat(expiration).isAfter(new Date());
  }

  @Test
  @DisplayName("Should extract issued at date from token")
  void shouldExtractIssuedAtDate() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    Date issuedAt = jwtService.extractClaim(token, claims -> claims.getIssuedAt());

    // Then
    assertThat(issuedAt).isNotNull();
    assertThat(issuedAt).isBeforeOrEqualTo(new Date());
  }

  @Test
  @DisplayName("Should extract issuer from token")
  void shouldExtractIssuer() {
    // Given
    String token = jwtService.generateToken(userDetails);

    // When
    String issuer = jwtService.extractClaim(token, claims -> claims.getIssuer());

    // Then
    assertThat(issuer).isEqualTo("test-auth-service");
  }

  @Test
  @DisplayName("Should handle multiple users with different tokens")
  void shouldHandleMultipleUsers() {
    // Given
    UserDetails user1 = new User("user1", "pass1",
        List.of(new SimpleGrantedAuthority("ROLE_USER")));
    UserDetails user2 = new User("user2", "pass2",
        List.of(new SimpleGrantedAuthority("ROLE_ADMIN")));

    // When
    String token1 = jwtService.generateToken(user1);
    String token2 = jwtService.generateToken(user2);

    // Then
    assertThat(jwtService.extractUsername(token1)).isEqualTo("user1");
    assertThat(jwtService.extractUsername(token2)).isEqualTo("user2");
    assertThat(jwtService.isTokenValid(token1, user1)).isTrue();
    assertThat(jwtService.isTokenValid(token2, user2)).isTrue();
    assertThat(jwtService.isTokenValid(token1, user2)).isFalse();
    assertThat(jwtService.isTokenValid(token2, user1)).isFalse();
  }

  @Test
  @DisplayName("Should get expiration time configuration")
  void shouldGetExpirationTime() {
    // When
    long expiration = jwtService.getExpirationTime();

    // Then
    assertThat(expiration).isEqualTo(3600000L); // 1 hour
  }

  @Test
  @DisplayName("Should get refresh expiration time configuration")
  void shouldGetRefreshExpirationTime() {
    // When
    long refreshExpiration = jwtService.getRefreshExpirationTime();

    // Then
    assertThat(refreshExpiration).isEqualTo(604800000L); // 7 days
  }

  @Test
  @DisplayName("Should get public key string")
  void shouldGetPublicKeyString() {
    // When
    String publicKey = jwtService.getPublicKeyString();

    // Then
    assertThat(publicKey).isNotNull();
    assertThat(publicKey).contains("BEGIN PUBLIC KEY");
    assertThat(publicKey).contains("END PUBLIC KEY");
  }

  @Test
  @DisplayName("Should extract all roles from token with multiple roles")
  void shouldExtractAllRoles() {
    // Given
    UserDetails multiRoleUser = new User("multirole", "password",
        List.of(
            new SimpleGrantedAuthority("ROLE_USER"),
            new SimpleGrantedAuthority("ROLE_ADMIN"),
            new SimpleGrantedAuthority("ROLE_MODERATOR")
        )
    );
    String token = jwtService.generateToken(multiRoleUser);

    // When
    List<String> roles = jwtService.extractRoles(token);

    // Then
    assertThat(roles).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MODERATOR");
  }

  @Test
  @DisplayName("Should handle user with no roles")
  void shouldHandleUserWithNoRoles() {
    // Given
    UserDetails noRoleUser = new User("norole", "password", List.of());
    String token = jwtService.generateToken(noRoleUser);

    // When
    List<String> roles = jwtService.extractRoles(token);

    // Then
    assertThat(roles).isEmpty();
  }

  @Test
  @DisplayName("Refresh token should have longer expiration than access token")
  void refreshTokenShouldHaveLongerExpiration() {
    // Given
    String accessToken = jwtService.generateToken(userDetails);
    String refreshToken = jwtService.generateRefreshToken(userDetails);

    // When
    Date accessExpiration = jwtService.extractClaim(accessToken, claims -> claims.getExpiration());
    Date refreshExpiration = jwtService.extractClaim(refreshToken,
        claims -> claims.getExpiration());

    // Then
    assertThat(refreshExpiration).isAfter(accessExpiration);
  }

  @Test
  @DisplayName("Should fail validation with tampered token")
  void shouldFailValidationWithTamperedToken() {
    // Given
    String token = jwtService.generateToken(userDetails);
    String tamperedToken = token.substring(0, token.length() - 10) + "tampered12";

    // When/Then
    assertThatThrownBy(() -> jwtService.isTokenValid(tamperedToken, userDetails))
        .isInstanceOf(SignatureException.class);
  }

  @Test
  @DisplayName("Should extract custom claim types correctly")
  void shouldExtractCustomClaimTypes() {
    // Given
    Map<String, Object> extraClaims = new HashMap<>();
    extraClaims.put("stringClaim", "value");
    extraClaims.put("intClaim", 42);
    extraClaims.put("booleanClaim", true);
    extraClaims.put("listClaim", List.of("item1", "item2"));

    String token = jwtService.generateToken(extraClaims, userDetails);

    // When/Then
    String stringValue = jwtService.extractClaim(token,
        claims -> claims.get("stringClaim", String.class));
    assertThat(stringValue).isEqualTo("value");

    Integer intValue = jwtService.extractClaim(token,
        claims -> claims.get("intClaim", Integer.class));
    assertThat(intValue).isEqualTo(42);

    Boolean booleanValue = jwtService.extractClaim(token,
        claims -> claims.get("booleanClaim", Boolean.class));
    assertThat(booleanValue).isTrue();

    @SuppressWarnings("unchecked")
    List<String> listValue = jwtService.extractClaim(token,
        claims -> claims.get("listClaim", List.class));
    assertThat(listValue).containsExactly("item1", "item2");
  }

  @Test
  @DisplayName("Tokens should be unique even for same user")
  void tokensShouldBeUnique(){
    // When
    String token1 = jwtService.generateToken(userDetails);
    String token2 = jwtService.generateToken(userDetails);

    // Then - tokens should be different due to different issuedAt timestamps
    assertThat(token1).isNotEqualTo(token2);
  }

  @Test
  @DisplayName("Should preserve username case sensitivity")
  void shouldPreserveUsernameCase() {
    // Given
    UserDetails mixedCaseUser = new User("TestUser123", "password",
        List.of(new SimpleGrantedAuthority("ROLE_USER")));
    String token = jwtService.generateToken(mixedCaseUser);

    // When
    String extractedUsername = jwtService.extractUsername(token);

    // Then
    assertThat(extractedUsername).isEqualTo("TestUser123");
  }
}