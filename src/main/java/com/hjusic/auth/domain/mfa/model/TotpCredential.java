package com.hjusic.auth.domain.mfa.model;

import com.hjusic.auth.domain.mfa.model.event.TotpCodeAcceptedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeRejectedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpDisabledEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEnrollmentConfirmedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEnrollmentStartedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEvent;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpAlgorithm;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpCode;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import io.vavr.control.Either;
import java.time.Duration;
import java.time.Instant;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;

/**
 * A user's TOTP authenticator. It starts unconfirmed when enrollment begins and only counts as a
 * second factor once the user proved possession by entering a valid code.
 */
@Getter
@Builder
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class TotpCredential {

  static final int MAX_FAILED_ATTEMPTS = 5;
  static final Duration LOCK_DURATION = Duration.ofMinutes(15);

  private static final long NO_STEP_USED = Long.MIN_VALUE;

  private final String username;
  private final TotpSecret secret;
  private final boolean confirmed;
  /** Time step of the last accepted code; codes from this step or earlier are rejected. */
  private final Long lastUsedTimeStep;
  private final int failedAttempts;
  private final Instant lockedUntil;

  public static TotpEnrollmentStartedEvent startEnrollment(String username, TotpSecret secret) {
    return TotpEnrollmentStartedEvent.of(username, secret);
  }

  public Either<MfaError, TotpEnrollmentConfirmedEvent> confirm(TotpCode code, Instant now) {
    if (confirmed) {
      return Either.left(MfaError.alreadyEnrolled());
    }
    var step = TotpAlgorithm.matchingTimeStep(secret, code, now, lastUsedStep());
    if (step.isEmpty()) {
      return Either.left(MfaError.invalidCode());
    }
    return Either.right(TotpEnrollmentConfirmedEvent.of(username, step.getAsLong()));
  }

  /**
   * Verifies a login code. Both outcomes of a real check are events, since a rejection must be
   * persisted too (it counts towards the lockout); {@code Left} means no check was possible.
   */
  public Either<MfaError, TotpEvent> verify(TotpCode code, Instant now) {
    if (!confirmed) {
      return Either.left(MfaError.notEnrolled(username));
    }
    if (isLocked(now)) {
      return Either.left(MfaError.locked(lockedUntil));
    }

    var step = TotpAlgorithm.matchingTimeStep(secret, code, now, lastUsedStep());
    if (step.isPresent()) {
      return Either.right(TotpCodeAcceptedEvent.of(username, step.getAsLong()));
    }

    int attempts = failedAttempts + 1;
    if (attempts >= MAX_FAILED_ATTEMPTS) {
      return Either.right(TotpCodeRejectedEvent.of(username, 0, now.plus(LOCK_DURATION)));
    }
    return Either.right(TotpCodeRejectedEvent.of(username, attempts, null));
  }

  public TotpDisabledEvent disable() {
    return TotpDisabledEvent.byUser(username);
  }

  public TotpDisabledEvent resetByAdmin() {
    return TotpDisabledEvent.byAdmin(username);
  }

  public boolean isLocked(Instant now) {
    return lockedUntil != null && now.isBefore(lockedUntil);
  }

  private long lastUsedStep() {
    return lastUsedTimeStep == null ? NO_STEP_USED : lastUsedTimeStep;
  }
}
