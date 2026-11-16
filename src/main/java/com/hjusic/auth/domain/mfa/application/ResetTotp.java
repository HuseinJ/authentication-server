package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Administrative removal of a user's authenticator, e.g. after the device was lost. */
@Service
@RequiredArgsConstructor
public class ResetTotp {

  private final TotpCredentials totpCredentials;

  @Transactional
  public Either<MfaError, Void> reset(String username) {
    var credential = totpCredentials.findByUsername(username);
    if (credential.isLeft()) {
      return Either.left(credential.getLeft());
    }
    totpCredentials.trigger(credential.get().resetByAdmin());
    return Either.right(null);
  }
}
