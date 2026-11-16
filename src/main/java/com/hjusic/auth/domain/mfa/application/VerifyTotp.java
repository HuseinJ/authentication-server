package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeAcceptedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeRejectedEvent;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpCode;
import io.vavr.control.Either;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Checks a login code for a user. Accepted codes are burned (no replay); rejected codes count
 * towards a temporary lockout.
 */
@Service
@RequiredArgsConstructor
public class VerifyTotp {

  private final TotpCredentials totpCredentials;
  private final Clock clock;

  @Transactional
  public Either<MfaError, Void> verify(String username, String rawCode) {
    var code = TotpCode.of(rawCode);
    if (code.isLeft()) {
      return Either.left(MfaError.invalidCode());
    }

    var credential = totpCredentials.findByUsername(username);
    if (credential.isLeft()) {
      return Either.left(credential.getLeft());
    }

    var outcome = credential.get().verify(code.get(), clock.instant());
    if (outcome.isLeft()) {
      return Either.left(outcome.getLeft());
    }

    return switch (outcome.get()) {
      case TotpCodeAcceptedEvent accepted -> totpCredentials.trigger(accepted)
          ? Either.right(null)
          : Either.left(MfaError.invalidCode());
      case TotpCodeRejectedEvent rejected -> {
        totpCredentials.trigger(rejected);
        yield Either.left(rejected.getLockedUntil() != null
            ? MfaError.locked(rejected.getLockedUntil())
            : MfaError.invalidCode());
      }
      default -> throw new IllegalStateException("Unexpected event " + outcome.get());
    };
  }
}
