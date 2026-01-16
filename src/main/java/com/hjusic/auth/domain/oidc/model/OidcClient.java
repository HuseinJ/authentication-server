package com.hjusic.auth.domain.oidc.model;

import com.hjusic.auth.domain.oidc.model.events.OAuthClientCreatedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientUpdatedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientDeletedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientSecretRegeneratedEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientName;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSecret;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import com.hjusic.auth.domain.oidc.model.valueObjects.Scope;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import io.vavr.control.Either;
import lombok.*;

import java.time.Instant;
import java.util.Set;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Data
@Builder
@EqualsAndHashCode(of = {"id"})
public class OidcClient {

  private OAuthClientId id;
  private ClientId clientId;
  private ClientSecret clientSecret;
  private ClientName clientName;
  private Set<AuthorizationGrantType> grantTypes;
  private Set<ClientAuthenticationMethod> authenticationMethods;
  private Set<RedirectUri> redirectUris;
  private Set<RedirectUri> postLogoutRedirectUris;
  private Set<Scope> scopes;
  private TokenSettings tokenSettings;
  private ClientSettings clientSettings;
  private Instant clientIdIssuedAt;

  public static Either<OAuthClientError, OAuthClientCreatedEvent> create(
      String clientId,
      String clientName,
      Set<String> grantTypes,
      Set<String> authenticationMethods,
      Set<String> redirectUris,
      Set<String> postLogoutRedirectUris,
      Set<String> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings,
      OidcClients clients) {

    // Validate clientId format
    var validatedClientId = ClientId.of(clientId);
    if (validatedClientId.isLeft()) {
      return Either.left(validatedClientId.getLeft());
    }

    // Check if client already exists
    if (clients.findByClientId(clientId).isDefined()) {
      return Either.left(OAuthClientError.clientAlreadyExists(clientId));
    }

    // Validate client name
    var validatedClientName = ClientName.of(clientName);
    if (validatedClientName.isLeft()) {
      return Either.left(validatedClientName.getLeft());
    }

    // Validate grant types
    var validatedGrantTypes = AuthorizationGrantType.ofSet(grantTypes);
    if (validatedGrantTypes.isLeft()) {
      return Either.left(validatedGrantTypes.getLeft());
    }

    // Validate authentication methods
    var validatedAuthMethods = ClientAuthenticationMethod.ofSet(authenticationMethods);
    if (validatedAuthMethods.isLeft()) {
      return Either.left(validatedAuthMethods.getLeft());
    }

    // Validate redirect URIs
    var validatedRedirectUris = RedirectUri.ofSet(redirectUris);
    if (validatedRedirectUris.isLeft()) {
      return Either.left(validatedRedirectUris.getLeft());
    }

    // Validate post-logout redirect URIs
    var validatedPostLogoutUris = RedirectUri.ofSet(postLogoutRedirectUris);
    if (validatedPostLogoutUris.isLeft()) {
      return Either.left(validatedPostLogoutUris.getLeft());
    }

    // Validate scopes
    var validatedScopes = Scope.ofSet(scopes);
    if (validatedScopes.isLeft()) {
      return Either.left(validatedScopes.getLeft());
    }

    // Generate client secret
    var clientSecret = ClientSecret.generate();

    var client = OidcClient.builder()
        .id(OAuthClientId.generate())
        .clientId(validatedClientId.get())
        .clientSecret(clientSecret)
        .clientName(validatedClientName.get())
        .grantTypes(validatedGrantTypes.get())
        .authenticationMethods(validatedAuthMethods.get())
        .redirectUris(validatedRedirectUris.get())
        .postLogoutRedirectUris(validatedPostLogoutUris.get())
        .scopes(validatedScopes.get())
        .tokenSettings(tokenSettings)
        .clientSettings(clientSettings)
        .clientIdIssuedAt(Instant.now())
        .build();

    return Either.right(OAuthClientCreatedEvent.of(client, clientSecret.getPlainText()));
  }

  public Either<OAuthClientError, OAuthClientUpdatedEvent> update(
      String clientName,
      Set<String> grantTypes,
      Set<String> redirectUris,
      Set<String> postLogoutRedirectUris,
      Set<String> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings) {

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

    this.clientName = validatedClientName.get();
    this.grantTypes = validatedGrantTypes.get();
    this.redirectUris = validatedRedirectUris.get();
    this.postLogoutRedirectUris = validatedPostLogoutUris.get();
    this.scopes = validatedScopes.get();
    this.tokenSettings = tokenSettings;
    this.clientSettings = clientSettings;

    return Either.right(OAuthClientUpdatedEvent.of(this));
  }

  public OAuthClientSecretRegeneratedEvent regenerateSecret() {
    var newSecret = ClientSecret.generate();
    this.clientSecret = newSecret;
    return OAuthClientSecretRegeneratedEvent.of(this, newSecret.getPlainText());
  }

  public OAuthClientDeletedEvent delete() {
    return OAuthClientDeletedEvent.of(this);
  }
}