package com.hjusic.auth.domain.mfa.model.valueObjects;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalLong;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * TOTP as specified in RFC 6238 (HMAC-SHA1, 30 second steps, 6 digits), which is what every
 * mainstream authenticator app implements. Spring Security has no TOTP verifier, so this is the
 * only hand-written crypto in the MFA flow.
 */
public final class TotpAlgorithm {

  public static final int DIGITS = 6;
  public static final Duration TIME_STEP = Duration.ofSeconds(30);

  /** Accept codes from one step before/after now to tolerate clock drift (RFC 6238 §5.2). */
  static final int ALLOWED_DRIFT_STEPS = 1;

  private static final String HMAC_ALGORITHM = "HmacSHA1";
  private static final int[] POWERS_OF_TEN = {1, 10, 100, 1_000, 10_000, 100_000, 1_000_000,
      10_000_000, 100_000_000};

  private TotpAlgorithm() {
  }

  public static long timeStep(Instant instant) {
    return Math.floorDiv(instant.getEpochSecond(), TIME_STEP.toSeconds());
  }

  public static String generate(TotpSecret secret, long timeStep) {
    return generate(secret, timeStep, DIGITS);
  }

  static String generate(TotpSecret secret, long timeStep, int digits) {
    byte[] hash = hmac(secret.getValue(), ByteBuffer.allocate(Long.BYTES).putLong(timeStep).array());
    int offset = hash[hash.length - 1] & 0x0F;
    int binary = ((hash[offset] & 0x7F) << 24)
        | ((hash[offset + 1] & 0xFF) << 16)
        | ((hash[offset + 2] & 0xFF) << 8)
        | (hash[offset + 3] & 0xFF);
    int otp = binary % POWERS_OF_TEN[digits];
    return String.format("%0" + digits + "d", otp);
  }

  /**
   * Finds the time step within the allowed drift window that produces {@code code}, ignoring
   * steps at or before {@code lastUsedTimeStep} so a code can never be replayed.
   */
  public static OptionalLong matchingTimeStep(TotpSecret secret, TotpCode code, Instant now,
      long lastUsedTimeStep) {
    long current = timeStep(now);
    byte[] expected = code.getValue().getBytes(StandardCharsets.US_ASCII);
    OptionalLong match = OptionalLong.empty();
    // Check every candidate (no early exit) so timing does not reveal which step matched.
    for (long step = current - ALLOWED_DRIFT_STEPS; step <= current + ALLOWED_DRIFT_STEPS; step++) {
      byte[] candidate = generate(secret, step).getBytes(StandardCharsets.US_ASCII);
      if (MessageDigest.isEqual(candidate, expected) && step > lastUsedTimeStep
          && match.isEmpty()) {
        match = OptionalLong.of(step);
      }
    }
    return match;
  }

  private static byte[] hmac(byte[] key, byte[] message) {
    try {
      Mac mac = Mac.getInstance(HMAC_ALGORITHM);
      mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
      return mac.doFinal(message);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA1 not available", e);
    }
  }
}
