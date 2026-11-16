package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpCode;
import io.vavr.control.Either;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Activates the pending authenticator once the user proves it produces valid codes. */
@Service
@RequiredArgsConstructor
public class ConfirmTotpEnrollment {

  private final Auth auth;
  private final TotpCredentials totpCredentials;
  private final Clock clock;

  @Transactional
  public Either<MfaError, Void> confirm(String rawCode) {
    var user = auth.findLoggedInUser();
    if (user.isLeft()) {
      return Either.left(MfaError.unauthenticated());
    }
    String username = user.get().getUsername().getValue();

    var code = TotpCode.of(rawCode);
    if (code.isLeft()) {
      return Either.left(code.getLeft());
    }

    var credential = totpCredentials.findByUsername(username);
    if (credential.isLeft()) {
      return Either.left(credential.getLeft());
    }

    var event = credential.get().confirm(code.get(), clock.instant());
    if (event.isLeft()) {
      return Either.left(event.getLeft());
    }

    if (!totpCredentials.trigger(event.get())) {
      return Either.left(MfaError.invalidCode());
    }
    return Either.right(null);
  }
}
