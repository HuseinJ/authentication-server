package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.AuthorizationGrantType;
import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientName;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import com.hjusic.auth.domain.oidc.model.valueObjects.Scope;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import io.vavr.control.Either;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UpdateOidcClient {

  private final OidcClients clients;

  public Either<OAuthClientError, OidcClient> update(
      String id,
      String clientName,
      Set<String> grantTypes,
      Set<String> redirectUris,
      Set<String> postLogoutRedirectUris,
      Set<String> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings) {

    var validatedId = OAuthClientId.of(id);
    if (validatedId.isLeft()) {
      return Either.left(validatedId.getLeft());
    }

    var existingClient = clients.findById(validatedId.get());
    if (existingClient.isEmpty()) {
      return Either.left(OAuthClientError.clientNotFound(id));
    }

    var validatedClientName = ClientName.of(clientName);
    if (validatedClientName.isLeft()) {
      return Either.left(validatedClientName.getLeft());
    }

    var validatedGrantTypes = AuthorizationGrantType.ofSet(grantTypes);
    if (validatedGrantTypes.isLeft()) {
      return Either.left(validatedGrantTypes.getLeft());
    }

    var validatedRedirectUris = RedirectUri.ofSet(redirectUris);
    if (validatedRedirectUris.isLeft()) {
      return Either.left(validatedRedirectUris.getLeft());
    }

    var validatedPostLogoutUris = RedirectUri.ofSet(postLogoutRedirectUris);
    if (validatedPostLogoutUris.isLeft()) {
      return Either.left(validatedPostLogoutUris.getLeft());
    }

    var validatedScopes = Scope.ofSet(scopes);
    if (validatedScopes.isLeft()) {
      return Either.left(validatedScopes.getLeft());
    }

    var client = existingClient.get();
    var event = client.update(
        validatedClientName.get(),
        validatedGrantTypes.get(),
        validatedRedirectUris.get(),
        validatedPostLogoutUris.get(),
        validatedScopes.get(),
        tokenSettings,
        clientSettings);

    return Either.right(clients.trigger(event));
  }
}