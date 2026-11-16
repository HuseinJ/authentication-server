package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Lets users remove their own authenticator. Requires the password and a current code, so a
 * stolen access token alone cannot strip the second factor.
 */
@Service
@RequiredArgsConstructor
public class DisableTotp {

  private final Auth auth;
  private final TotpCredentials totpCredentials;
  private final VerifyTotp verifyTotp;

  @Transactional
  public Either<MfaError, Void> disable(String currentPassword, String code) {
    var user = auth.findLoggedInUser();
    if (user.isLeft()) {
      return Either.left(MfaError.unauthenticated());
    }
    String username = user.get().getUsername().getValue();

    var passwordMatches = auth.matchesCurrentPassword(currentPassword);
    if (passwordMatches.isLeft() || !passwordMatches.get()) {
      return Either.left(MfaError.validationFailed("Password does not match"));
    }

    var verified = verifyTotp.verify(username, code);
    if (verified.isLeft()) {
      return verified;
    }

    var credential = totpCredentials.findByUsername(username);
    if (credential.isLeft()) {
      return Either.left(credential.getLeft());
    }
    totpCredentials.trigger(credential.get().disable());
    return Either.right(null);
  }
}
