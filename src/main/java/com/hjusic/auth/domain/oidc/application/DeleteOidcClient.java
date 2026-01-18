package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeleteOidcClient {

  private final OidcClients clients;

  public Either<OAuthClientError, OidcClient> delete(String id) {

    var validatedId = OAuthClientId.of(id);
    if (validatedId.isLeft()) {
      return Either.left(validatedId.getLeft());
    }

    var existingClient = clients.findById(validatedId.get());
    if (existingClient.isEmpty()) {
      return Either.left(OAuthClientError.clientNotFound(id));
    }

    var client = existingClient.get();
    var event = client.delete();

    return Either.right(clients.trigger(event));
  }
}
