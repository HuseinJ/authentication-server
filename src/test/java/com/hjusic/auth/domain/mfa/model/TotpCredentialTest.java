package com.hjusic.auth.domain.mfa.model;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.domain.mfa.model.event.TotpCodeAcceptedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeRejectedEvent;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpAlgorithm;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpCode;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TotpCredentialTest {

  private static final Instant NOW = Instant.ofEpochSecond(1_700_000_000L);
  private static final long STEP = TotpAlgorithm.timeStep(NOW);

  private final TotpSecret secret = TotpSecret.generate();

  @Test
  @DisplayName("confirming with a valid code yields a confirmation for that step")
  void confirmWithValidCode() {
    var credential = pending();

    var result = credential.confirm(code(STEP), NOW);

    assertThat(result.isRight()).isTrue();
    assertThat(result.get().getTimeStep()).isEqualTo(STEP);
    assertThat(result.get().getUsername()).isEqualTo("alice");
  }

  @Test
  @DisplayName("confirming with a wrong code fails")
  void confirmWithInvalidCode() {
    var result = pending().confirm(code(STEP + 5), NOW);

    assertThat(result.getLeft().getCode()).isEqualTo(MfaErrorCode.INVALID_CODE);
  }

  @Test
  @DisplayName("an already confirmed credential cannot be confirmed again")
  void confirmTwice() {
    var result = confirmed(STEP - 1, 0, null).confirm(code(STEP), NOW);

    assertThat(result.getLeft().getCode()).isEqualTo(MfaErrorCode.ALREADY_ENROLLED);
  }

  @Test
  @DisplayName("a pending (unconfirmed) credential cannot be used to log in")
  void verifyPending() {
    var result = pending().verify(code(STEP), NOW);

    assertThat(result.getLeft().getCode()).isEqualTo(MfaErrorCode.NOT_ENROLLED);
  }

  @Test
  @DisplayName("a valid code is accepted and reports its time step")
  void verifyValid() {
    var result = confirmed(STEP - 1, 0, null).verify(code(STEP), NOW);

    assertThat(result.get()).isInstanceOf(TotpCodeAcceptedEvent.class);
    assertThat(((TotpCodeAcceptedEvent) result.get()).getTimeStep()).isEqualTo(STEP);
  }

  @Test
  @DisplayName("a code from an already used step is rejected")
  void verifyReplay() {
    var result = confirmed(STEP, 0, null).verify(code(STEP), NOW);

    assertThat(result.get()).isInstanceOf(TotpCodeRejectedEvent.class);
  }

  @Test
  @DisplayName("wrong codes count up and lock the credential at the limit")
  void lockoutAfterMaxFailures() {
    var almostLocked = confirmed(null, TotpCredential.MAX_FAILED_ATTEMPTS - 2, null);
    var rejected = (TotpCodeRejectedEvent) almostLocked.verify(code(STEP + 5), NOW).get();
    assertThat(rejected.getFailedAttempts()).isEqualTo(TotpCredential.MAX_FAILED_ATTEMPTS - 1);
    assertThat(rejected.getLockedUntil()).isNull();

    var atLimit = confirmed(null, TotpCredential.MAX_FAILED_ATTEMPTS - 1, null);
    var locking = (TotpCodeRejectedEvent) atLimit.verify(code(STEP + 5), NOW).get();
    assertThat(locking.getLockedUntil()).isEqualTo(NOW.plus(TotpCredential.LOCK_DURATION));
    assertThat(locking.getFailedAttempts()).isZero();
  }

  @Test
  @DisplayName("a locked credential rejects even valid codes until the lock expires")
  void lockedCredential() {
    Instant lockedUntil = NOW.plusSeconds(60);
    var locked = confirmed(null, 0, lockedUntil);

    assertThat(locked.verify(code(STEP), NOW).getLeft().getCode())
        .isEqualTo(MfaErrorCode.LOCKED);

    Instant afterLock = lockedUntil.plusSeconds(1);
    long stepAfterLock = TotpAlgorithm.timeStep(afterLock);
    assertThat(locked.verify(code(stepAfterLock), afterLock).get())
        .isInstanceOf(TotpCodeAcceptedEvent.class);
  }

  private TotpCredential pending() {
    return TotpCredential.builder().username("alice").secret(secret).confirmed(false).build();
  }

  private TotpCredential confirmed(Long lastUsedStep, int failedAttempts, Instant lockedUntil) {
    return TotpCredential.builder()
        .username("alice")
        .secret(secret)
        .confirmed(true)
        .lastUsedTimeStep(lastUsedStep)
        .failedAttempts(failedAttempts)
        .lockedUntil(lockedUntil)
        .build();
  }

  private TotpCode code(long step) {
    return TotpCode.of(TotpAlgorithm.generate(secret, step)).get();
  }
}
