package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RegenerateOidcClientSecret {

  private final OidcClients clients;
  private final PasswordEncoder passwordEncoder;

  public Either<OAuthClientError, RegenerateSecretResult> regenerate(String id) {

    var validatedId = OAuthClientId.of(id);
    if (validatedId.isLeft()) {
      return Either.left(validatedId.getLeft());
    }

    var existingClient = clients.findById(validatedId.get());
    if (existingClient.isEmpty()) {
      return Either.left(OAuthClientError.clientNotFound(id));
    }

    var client = existingClient.get();
    var event = client.regenerateSecret(passwordEncoder);
    var updatedClient = clients.trigger(event);

    return Either.right(new RegenerateSecretResult(updatedClient, event.getNewClientSecret().getPlainText()));
  }

  public record RegenerateSecretResult(
      com.hjusic.auth.domain.oidc.model.OidcClient client,
      String plainTextSecret) {}
}