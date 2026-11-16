package com.hjusic.auth.domain.mfa.model;

import com.hjusic.auth.domain.mfa.model.event.TotpEvent;
import io.vavr.control.Either;

public interface TotpCredentials {

  Either<MfaError, TotpCredential> findByUsername(String username);

  /**
   * Applies and publishes the event.
   *
   * @return {@code false} if the event lost a race against a concurrent change and was not
   * applied, e.g. the same code being redeemed by two requests at once.
   */
  boolean trigger(TotpEvent event);
}
