package com.hjusic.auth.domain.mfa.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TotpAlgorithmTest {

  /** RFC 6238 Appendix B shared secret for HMAC-SHA1. */
  private static final TotpSecret RFC_SECRET =
      TotpSecret.of("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

  @ParameterizedTest(name = "T={0} -> {1}")
  @CsvSource({
      "59, 94287082",
      "1111111109, 07081804",
      "1111111111, 14050471",
      "1234567890, 89005924",
      "2000000000, 69279037",
      "20000000000, 65353130"
  })
  @DisplayName("matches the RFC 6238 SHA1 test vectors")
  void rfc6238TestVectors(long epochSeconds, String expected) {
    long step = TotpAlgorithm.timeStep(Instant.ofEpochSecond(epochSeconds));

    assertThat(TotpAlgorithm.generate(RFC_SECRET, step, 8)).isEqualTo(expected);
    assertThat(TotpAlgorithm.generate(RFC_SECRET, step))
        .isEqualTo(expected.substring(2));
  }

  @Test
  @DisplayName("accepts codes from the previous, current and next time step")
  void toleratesOneStepOfDrift() {
    Instant now = Instant.ofEpochSecond(1_700_000_000L);
    long current = TotpAlgorithm.timeStep(now);

    for (long step = current - 1; step <= current + 1; step++) {
      TotpCode code = TotpCode.of(TotpAlgorithm.generate(RFC_SECRET, step)).get();
      assertThat(TotpAlgorithm.matchingTimeStep(RFC_SECRET, code, now, Long.MIN_VALUE))
          .hasValue(step);
    }
  }

  @Test
  @DisplayName("rejects codes outside the drift window")
  void rejectsCodesOutsideWindow() {
    Instant now = Instant.ofEpochSecond(1_700_000_000L);
    long current = TotpAlgorithm.timeStep(now);

    TotpCode old = TotpCode.of(TotpAlgorithm.generate(RFC_SECRET, current - 2)).get();
    TotpCode future = TotpCode.of(TotpAlgorithm.generate(RFC_SECRET, current + 2)).get();

    assertThat(TotpAlgorithm.matchingTimeStep(RFC_SECRET, old, now, Long.MIN_VALUE)).isEmpty();
    assertThat(TotpAlgorithm.matchingTimeStep(RFC_SECRET, future, now, Long.MIN_VALUE)).isEmpty();
  }

  @Test
  @DisplayName("rejects codes from already used time steps (replay)")
  void rejectsReplayedSteps() {
    Instant now = Instant.ofEpochSecond(1_700_000_000L);
    long current = TotpAlgorithm.timeStep(now);
    TotpCode code = TotpCode.of(TotpAlgorithm.generate(RFC_SECRET, current)).get();

    assertThat(TotpAlgorithm.matchingTimeStep(RFC_SECRET, code, now, current)).isEmpty();
    assertThat(TotpAlgorithm.matchingTimeStep(RFC_SECRET, code, now, current - 1))
        .hasValue(current);
  }
}
