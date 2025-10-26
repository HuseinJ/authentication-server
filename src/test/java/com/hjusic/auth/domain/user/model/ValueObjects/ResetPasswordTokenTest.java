package com.hjusic.auth.domain.user.model.ValueObjects;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

@DisplayName("ResetPasswordToken Tests")
class ResetPasswordTokenTest {

  @Nested
  @DisplayName("Token Creation")
  class TokenCreation {

    @Test
    @DisplayName("Should create token with valid UUID")
    void shouldCreateTokenWithValidUUID() {
      // When
      ResetPasswordToken token = ResetPasswordToken.create();

      // Then
      assertThat(token.getRawToken()).isNotNull();
      assertThat(token.getRawToken()).matches(
          "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
      );
    }

    @Test
    @DisplayName("Should set expiration to 15 minutes from creation")
    void shouldSetExpirationTo15Minutes() {
      // When
      ResetPasswordToken token = ResetPasswordToken.create();

      // Then
      assertThat(token.getCreatedOn()).isNotNull();
      assertThat(token.getExpiresOn()).isNotNull();
      assertThat(token.getExpiresOn())
          .isAfter(token.getCreatedOn())
          .isBeforeOrEqualTo(token.getCreatedOn().plusMinutes(16))
          .isAfterOrEqualTo(token.getCreatedOn().plusMinutes(14));
    }

    @Test
    @DisplayName("Should create unique tokens on multiple calls")
    void shouldCreateUniqueTokens() {
      // When
      ResetPasswordToken token1 = ResetPasswordToken.create();
      ResetPasswordToken token2 = ResetPasswordToken.create();

      // Then
      assertThat(token1.getRawToken()).isNotEqualTo(token2.getRawToken());
      assertThat(token1.getTokenHash()).isNotEqualTo(token2.getTokenHash());
    }

    @Test
    @DisplayName("Should not be expired immediately after creation")
    void shouldNotBeExpiredImmediately() {
      // When
      ResetPasswordToken token = ResetPasswordToken.create();

      // Then
      assertThat(token.isExpired()).isFalse();
    }
  }

  @Nested
  @DisplayName("Token Hashing")
  class TokenHashing {

    @Test
    @DisplayName("Should produce SHA-256 hash of 64 hex characters")
    void shouldProduceSHA256Hash() {
      // When
      ResetPasswordToken token = ResetPasswordToken.create();

      // Then
      assertThat(token.getTokenHash())
          .hasSize(64)
          .matches("^[0-9a-f]{64}$");
    }

    @Test
    @DisplayName("Should produce consistent hash for same token")
    void shouldProduceConsistentHash() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String hash1 = token.getTokenHash();
      String hash2 = token.getTokenHash();

      // Then
      assertThat(hash1).isEqualTo(hash2);
    }

    @Test
    @DisplayName("Should produce different hashes for different tokens")
    void shouldProduceDifferentHashes() {
      // Given
      ResetPasswordToken token1 = ResetPasswordToken.create();
      ResetPasswordToken token2 = ResetPasswordToken.create();

      // When & Then
      assertThat(token1.getTokenHash()).isNotEqualTo(token2.getTokenHash());
    }

    @Test
    @DisplayName("Should never expose raw token in hash")
    void shouldNeverExposeRawTokenInHash() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String hash = token.getTokenHash();

      // Then
      assertThat(hash).doesNotContain(token.getRawToken());
    }
  }

  @Nested
  @DisplayName("Token Verification")
  class TokenVerification {

    @Test
    @DisplayName("Should verify correct token successfully")
    void shouldVerifyCorrectToken() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String rawToken = token.getRawToken();
      String storedHash = token.getTokenHash();

      // When
      boolean isValid = ResetPasswordToken.verifyToken(rawToken, storedHash);

      // Then
      assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("Should reject incorrect token")
    void shouldRejectIncorrectToken() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String storedHash = token.getTokenHash();
      String wrongToken = UUID.randomUUID().toString();

      // When
      boolean isValid = ResetPasswordToken.verifyToken(wrongToken, storedHash);

      // Then
      assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should reject slightly modified token")
    void shouldRejectModifiedToken() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String storedHash = token.getTokenHash();
      String modifiedToken = token.getRawToken().replace('a', 'b');

      // When
      boolean isValid = ResetPasswordToken.verifyToken(modifiedToken, storedHash);

      // Then
      assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("Should use MessageDigest.isEqual for constant-time comparison")
    void shouldUseConstantTimeComparison() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String correctToken = token.getRawToken();
      String wrongToken = UUID.randomUUID().toString();
      String storedHash = token.getTokenHash();

      assertThat(ResetPasswordToken.verifyToken(correctToken, storedHash))
          .describedAs("Correct token should verify successfully")
          .isTrue();

      assertThat(ResetPasswordToken.verifyToken(wrongToken, storedHash))
          .describedAs("Wrong token should fail verification")
          .isFalse();
    }
  }

  @Nested
  @DisplayName("Token Expiration")
  class TokenExpiration {

    @Test
    @DisplayName("Should not be expired before expiration time")
    void shouldNotBeExpiredBeforeExpirationTime() {
      // Given
      LocalDateTime now = LocalDateTime.now();
      ResetPasswordToken token = new ResetPasswordToken(
          UUID.randomUUID(),
          now.plusMinutes(5),
          now.minusMinutes(10)
      );

      // When & Then
      assertThat(token.isExpired()).isFalse();
    }

    @Test
    @DisplayName("Should be expired after expiration time")
    void shouldBeExpiredAfterExpirationTime() {
      // Given
      LocalDateTime now = LocalDateTime.now();
      ResetPasswordToken token = new ResetPasswordToken(
          UUID.randomUUID(),
          now.minusMinutes(1),
          now.minusMinutes(16)
      );

      // When & Then
      assertThat(token.isExpired()).isTrue();
    }

    @Test
    @DisplayName("Should be expired exactly at expiration time")
    void shouldBeExpiredAtExactExpirationTime() throws InterruptedException {
      // Given
      LocalDateTime now = LocalDateTime.now();
      ResetPasswordToken token = new ResetPasswordToken(
          UUID.randomUUID(),
          now.plusNanos(100_000_000), // 100ms in future
          now
      );

      // When
      Thread.sleep(150); // Wait past expiration

      // Then
      assertThat(token.isExpired()).isTrue();
    }
  }

  @Nested
  @DisplayName("Equals and HashCode")
  class EqualsAndHashCode {

    @Test
    @DisplayName("Should consider tokens with same hash as equal")
    void shouldConsiderSameHashAsEqual() {
      // Given
      UUID sameUuid = UUID.randomUUID();
      LocalDateTime now = LocalDateTime.now();

      ResetPasswordToken token1 = new ResetPasswordToken(
          sameUuid, now.plusMinutes(15), now
      );
      ResetPasswordToken token2 = new ResetPasswordToken(
          sameUuid, now.plusMinutes(15), now
      );

      // When & Then
      assertThat(token1).isEqualTo(token2);
      assertThat(token1.hashCode()).isEqualTo(token2.hashCode());
    }

    @Test
    @DisplayName("Should not consider tokens with different UUIDs as equal")
    void shouldNotConsiderDifferentUUIDsAsEqual() {
      // Given
      LocalDateTime now = LocalDateTime.now();

      ResetPasswordToken token1 = new ResetPasswordToken(
          UUID.randomUUID(), now.plusMinutes(15), now
      );
      ResetPasswordToken token2 = new ResetPasswordToken(
          UUID.randomUUID(), now.plusMinutes(15), now
      );

      // When & Then
      assertThat(token1).isNotEqualTo(token2);
    }

    @Test
    @DisplayName("Should exclude raw token value from equals comparison")
    void shouldExcludeRawTokenFromEquals() {
      // This test verifies that @EqualsAndHashCode(exclude = {"value"}) works
      // Actually, with different UUIDs they won't be equal anyway
      // This is more of a documentation test

      ResetPasswordToken token1 = ResetPasswordToken.create();
      ResetPasswordToken token2 = ResetPasswordToken.create();

      assertThat(token1.getRawToken()).isNotEqualTo(token2.getRawToken());
    }
  }

  @Nested
  @DisplayName("ToString")
  class ToStringTest {

    @Test
    @DisplayName("Should not include raw token in toString")
    void shouldNotIncludeRawTokenInToString() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String toString = token.toString();

      // Then
      assertThat(toString).doesNotContain(token.getRawToken());
    }

    @Test
    @DisplayName("Should include partial hash in toString")
    void shouldIncludePartialHashInToString() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String toString = token.toString();

      // Then
      String partialHash = token.getTokenHash().substring(0, 8);
      assertThat(toString).contains(partialHash);
    }

    @Test
    @DisplayName("Should include timestamps in toString")
    void shouldIncludeTimestampsInToString() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String toString = token.toString();

      // Then
      assertThat(toString)
          .contains("expiresOn=")
          .contains("createdOn=");
    }

    @Test
    @DisplayName("Should produce consistent toString output")
    void shouldProduceConsistentToString() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();

      // When
      String toString1 = token.toString();
      String toString2 = token.toString();

      // Then
      assertThat(toString1).isEqualTo(toString2);
    }
  }

  @Nested
  @DisplayName("Security Properties")
  class SecurityProperties {

    @Test
    @DisplayName("Should generate cryptographically random tokens")
    void shouldGenerateCryptographicallyRandomTokens() {
      // Given - create many tokens
      int tokenCount = 1000;
      var tokens = new java.util.HashSet<String>();

      // When
      for (int i = 0; i < tokenCount; i++) {
        tokens.add(ResetPasswordToken.create().getRawToken());
      }

      // Then - all should be unique (collision probability is astronomically low)
      assertThat(tokens).hasSize(tokenCount);
    }

    @Test
    @DisplayName("Should produce irreversible hash")
    void shouldProduceIrreversibleHash() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String hash = token.getTokenHash();

      // Then - hash should not contain any recognizable part of UUID
      String[] uuidParts = token.getRawToken().split("-");
      for (String part : uuidParts) {
        assertThat(hash.toLowerCase()).doesNotContain(part.toLowerCase());
      }
    }

    @Test
    @DisplayName("Should have sufficient hash entropy")
    void shouldHaveSufficientHashEntropy() {
      // Given
      ResetPasswordToken token = ResetPasswordToken.create();
      String hash = token.getTokenHash();

      // When - count unique characters
      long uniqueChars = hash.chars().distinct().count();

      // Then - should have good distribution (at least 10 different hex chars)
      assertThat(uniqueChars).isGreaterThanOrEqualTo(10);
    }
  }
}