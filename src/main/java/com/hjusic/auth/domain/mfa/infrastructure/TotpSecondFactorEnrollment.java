package com.hjusic.auth.domain.mfa.infrastructure;

import com.hjusic.auth.domain.mfa.model.SecondFactorEnrollment;
import com.hjusic.auth.domain.mfa.model.SecondFactorType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
class TotpSecondFactorEnrollment implements SecondFactorEnrollment {

  private final TotpCredentialDatabaseRepository repository;

  @Override
  public SecondFactorType type() {
    return SecondFactorType.TOTP;
  }

  @Override
  public boolean isEnrolled(String username) {
    return repository.existsByUserUsernameAndConfirmedTrue(username);
  }
}
