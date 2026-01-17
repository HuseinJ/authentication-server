package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.AuthorizationGrantType;
import com.hjusic.auth.domain.oidc.model.ClientAuthenticationMethod;
import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientName;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSecret;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import com.hjusic.auth.domain.oidc.model.valueObjects.Scope;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import io.vavr.control.Either;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateOidcClient {

  private final OidcClients clients;
  private final PasswordEncoder passwordEncoder;

  public Either<OAuthClientError, OidcClient> create(
      String clientId,
      String clientName,
      Set<String> grantTypes,
      Set<String> authenticationMethods,
      Set<String> redirectUris,
      Set<String> postLogoutRedirectUris,
      Set<String> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings) {

    var validatedClientId = ClientId.of(clientId);
    if (validatedClientId.isLeft()) {
      return Either.left(validatedClientId.getLeft());
    }

    if (clients.findByClientId(validatedClientId.get()).isPresent()) {
      return Either.left(OAuthClientError.clientAlreadyExists(clientId));
    }

    var validatedClientName = ClientName.of(clientName);
    if (validatedClientName.isLeft()) {
      return Either.left(validatedClientName.getLeft());
    }

    var validatedGrantTypes = AuthorizationGrantType.ofSet(grantTypes);
    if (validatedGrantTypes.isLeft()) {
      return Either.left(validatedGrantTypes.getLeft());
    }

    var validatedAuthMethods = ClientAuthenticationMethod.ofSet(authenticationMethods);
    if (validatedAuthMethods.isLeft()) {
      return Either.left(validatedAuthMethods.getLeft());
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

    var clientSecret = ClientSecret.generate(passwordEncoder);

    var event = OidcClient.create(validatedClientId.get(), validatedClientName.get(),
        validatedGrantTypes.get(), validatedAuthMethods.get(),
        validatedRedirectUris.get(), validatedPostLogoutUris.get(),
        validatedScopes.get(), tokenSettings, clientSettings, clientSecret);

    var resultClient = clients.trigger(event);
    resultClient.setClientSecret(clientSecret);

    return Either.right(resultClient);
  }

}
