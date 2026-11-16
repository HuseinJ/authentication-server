package com.hjusic.auth.domain.mfa.infrastructure;

import com.hjusic.auth.domain.mfa.model.MfaError;
import com.hjusic.auth.domain.mfa.model.TotpCredential;
import com.hjusic.auth.domain.mfa.model.TotpCredentials;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeAcceptedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpCodeRejectedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpDisabledEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEnrollmentConfirmedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEnrollmentStartedEvent;
import com.hjusic.auth.domain.mfa.model.event.TotpEvent;
import com.hjusic.auth.domain.user.infrastructure.UserDatabaseRepository;
import com.hjusic.auth.event.model.DomainEventPublisher;
import io.vavr.control.Either;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class TotpCredentialAppRepository implements TotpCredentials {

  private final TotpCredentialDatabaseRepository repository;
  private final UserDatabaseRepository userRepository;
  private final TotpSecretCipher cipher;
  private final DomainEventPublisher domainEventPublisher;

  @Override
  public Either<MfaError, TotpCredential> findByUsername(String username) {
    return repository.findByUserUsername(username)
        .map(entity -> Either.<MfaError, TotpCredential>right(toModel(entity, username)))
        .orElse(Either.left(MfaError.notEnrolled(username)));
  }

  @Override
  public boolean trigger(TotpEvent event) {
    boolean applied = switch (event) {
      case TotpEnrollmentStartedEvent e -> handle(e);
      case TotpEnrollmentConfirmedEvent e ->
          repository.markTimeStepUsed(e.getUsername(), e.getTimeStep(), Instant.now()) == 1;
      case TotpCodeAcceptedEvent e ->
          repository.markTimeStepUsed(e.getUsername(), e.getTimeStep(), Instant.now()) == 1;
      case TotpCodeRejectedEvent e -> handle(e);
      case TotpDisabledEvent e -> repository.deleteByUsername(e.getUsername()) > 0;
      default -> throw new IllegalArgumentException("Unhandled event type: " + event.getClass());
    };

    if (applied) {
      domainEventPublisher.publish(event);
    }
    return applied;
  }

  private boolean handle(TotpEnrollmentStartedEvent e) {
    var user = userRepository.findByUsername(e.getUsername()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername()));

    var entity = repository.findByUserUsername(e.getUsername())
        .orElseGet(() -> TotpCredentialDatabaseEntity.builder().user(user).build());
    entity.setEncryptedSecret(cipher.encrypt(e.getSecret()));
    entity.setConfirmed(false);
    entity.setLastUsedTimeStep(null);
    entity.setFailedAttempts(0);
    entity.setLockedUntil(null);
    repository.save(entity);
    return true;
  }

  private boolean handle(TotpCodeRejectedEvent e) {
    var entity = repository.findByUserUsername(e.getUsername()).orElseThrow(
        () -> new IllegalArgumentException("No TOTP credential for: " + e.getUsername()));
    entity.setFailedAttempts(e.getFailedAttempts());
    entity.setLockedUntil(e.getLockedUntil());
    repository.save(entity);
    return true;
  }

  private TotpCredential toModel(TotpCredentialDatabaseEntity entity, String username) {
    return TotpCredential.builder()
        .username(username)
        .secret(cipher.decrypt(entity.getEncryptedSecret()))
        .confirmed(entity.isConfirmed())
        .lastUsedTimeStep(entity.getLastUsedTimeStep())
        .failedAttempts(entity.getFailedAttempts())
        .lockedUntil(entity.getLockedUntil())
        .build();
  }
}
