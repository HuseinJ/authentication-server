package com.hjusic.auth.domain.mfa.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredential;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import com.hjusic.auth.domain.mfa.model.valueObjects.TotpSecret;
import io.vavr.control.Either;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Generates a new secret for the logged-in user. Calling it again before confirming replaces the
 * pending secret; an already confirmed authenticator has to be disabled first.
 */
@Service
public class StartTotpEnrollment {

  private final Auth auth;
  private final TotpCredentials totpCredentials;
  private final String issuer;

  public StartTotpEnrollment(Auth auth, TotpCredentials totpCredentials,
      @Value("${auth.mfa.totp.issuer:Authentication Server}") String issuer) {
    this.auth = auth;
    this.totpCredentials = totpCredentials;
    this.issuer = issuer;
  }

  @Transactional
  public Either<MfaError, TotpEnrollmentDetails> start() {
    var user = auth.findLoggedInUser();
    if (user.isLeft()) {
      return Either.left(MfaError.unauthenticated());
    }
    String username = user.get().getUsername().getValue();

    var existing = totpCredentials.findByUsername(username);
    if (existing.isRight() && existing.get().isConfirmed()) {
      return Either.left(MfaError.alreadyEnrolled());
    }

    TotpSecret secret = TotpSecret.generate();
    totpCredentials.trigger(TotpCredential.startEnrollment(username, secret));

    return Either.right(new TotpEnrollmentDetails(
        secret.toBase32(),
        secret.toOtpAuthUri(issuer, username)));
  }
}
