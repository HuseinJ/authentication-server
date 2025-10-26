package com.hjusic.auth.domain.user.model.ValueObjects;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public class ResetPasswordToken {

  private static final int EXPIRATION_IN_MINUTES = 15;

  private final UUID value;
  private final LocalDateTime expiresOn;
  private final LocalDateTime createdOn;

  public static ResetPasswordToken create() {
    LocalDateTime now = LocalDateTime.now();
    return new ResetPasswordToken(
        UUID.randomUUID(),
        now.plusMinutes(EXPIRATION_IN_MINUTES),
        now
    );
  }

  public String getRawToken() {
    return value.toString();
  }

  public String getTokenHash() {
    return hashToken(value.toString());
  }

  public static boolean verifyToken(String rawToken, String storedHash) {
    String computedHash = hashToken(rawToken);
    return MessageDigest.isEqual(
        computedHash.getBytes(StandardCharsets.UTF_8),
        storedHash.getBytes(StandardCharsets.UTF_8)
    );
  }

  public boolean isExpired() {
    return LocalDateTime.now().isAfter(expiresOn);
  }

  private static String hashToken(String rawToken) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
      return bytesToHex(hash);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 algorithm not available", e);
    }
  }

  private static String bytesToHex(byte[] hash) {
    StringBuilder hexString = new StringBuilder(2 * hash.length);
    for (byte b : hash) {
      String hex = Integer.toHexString(0xff & b);
      if (hex.length() == 1) {
        hexString.append('0');
      }
      hexString.append(hex);
    }
    return hexString.toString();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    ResetPasswordToken that = (ResetPasswordToken) o;
    return value.equals(that.value); // Compare by UUID only
  }

  @Override
  public int hashCode() {
    return value.hashCode(); // Hash by UUID only
  }

  @Override
  public String toString() {
    return "ResetPasswordToken{" +
        "tokenHash='" + getTokenHash().substring(0, 8) + "...', " +
        "expiresOn=" + expiresOn +
        ", createdOn=" + createdOn +
        '}';
  }
}