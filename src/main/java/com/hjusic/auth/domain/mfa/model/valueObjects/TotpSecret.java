package com.hjusic.auth.domain.mfa.model.valueObjects;

import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;

/**
 * Shared TOTP secret (RFC 6238). 160 bits, as recommended by RFC 4226 for HMAC-SHA1.
 * Authenticator apps receive it Base32-encoded inside an {@code otpauth://} URI.
 */
public final class TotpSecret {

  private static final int SECRET_BYTES = 20;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  private final byte[] value;

  private TotpSecret(byte[] value) {
    this.value = value.clone();
  }

  public static TotpSecret generate() {
    byte[] bytes = new byte[SECRET_BYTES];
    RANDOM.nextBytes(bytes);
    return new TotpSecret(bytes);
  }

  public static TotpSecret of(byte[] value) {
    if (value == null || value.length < 10) {
      throw new IllegalArgumentException("TOTP secret must be at least 80 bits");
    }
    return new TotpSecret(value);
  }

  public static TotpSecret fromBase32(String base32) {
    String normalized = base32.replace("=", "").replace(" ", "").toUpperCase(Locale.ROOT);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int buffer = 0;
    int bits = 0;
    for (char c : normalized.toCharArray()) {
      int index = BASE32_ALPHABET.indexOf(c);
      if (index < 0) {
        throw new IllegalArgumentException("Invalid Base32 character: " + c);
      }
      buffer = (buffer << 5) | index;
      bits += 5;
      if (bits >= 8) {
        out.write((buffer >> (bits - 8)) & 0xFF);
        bits -= 8;
      }
    }
    return of(out.toByteArray());
  }

  public byte[] getValue() {
    return value.clone();
  }

  /** RFC 4648 Base32 without padding, the format authenticator apps expect. */
  public String toBase32() {
    StringBuilder result = new StringBuilder();
    int buffer = 0;
    int bits = 0;
    for (byte b : value) {
      buffer = (buffer << 8) | (b & 0xFF);
      bits += 8;
      while (bits >= 5) {
        result.append(BASE32_ALPHABET.charAt((buffer >> (bits - 5)) & 0x1F));
        bits -= 5;
      }
    }
    if (bits > 0) {
      result.append(BASE32_ALPHABET.charAt((buffer << (5 - bits)) & 0x1F));
    }
    return result.toString();
  }

  /**
   * Key URI understood by Google Authenticator, Aegis, 1Password, etc.
   * See https://github.com/google/google-authenticator/wiki/Key-Uri-Format
   */
  public String toOtpAuthUri(String issuer, String accountName) {
    String label = encode(issuer) + ":" + encode(accountName);
    return "otpauth://totp/" + label
        + "?secret=" + toBase32()
        + "&issuer=" + encode(issuer)
        + "&algorithm=SHA1&digits=" + TotpAlgorithm.DIGITS
        + "&period=" + TotpAlgorithm.TIME_STEP.toSeconds();
  }

  private static String encode(String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof TotpSecret other && Arrays.equals(value, other.value);
  }

  @Override
  public int hashCode() {
    return Arrays.hashCode(value);
  }

  @Override
  public String toString() {
    return "TotpSecret[****]";
  }
}
