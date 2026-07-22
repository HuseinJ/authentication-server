package com.hjusic.auth.domain.oidc.api;

import com.hjusic.auth.domain.oidc.model.AuthorizationGrantType;
import com.hjusic.auth.domain.oidc.model.ClientAuthenticationMethod;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import com.hjusic.auth.domain.oidc.model.valueObjects.Scope;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * API response representation of an OIDC client.
 *
 * <p>This is the explicit wire contract for the client-management endpoints. It exists so that
 * (a) the client secret is never serialized (it is not present here at all), and (b) the response
 * shape is decoupled from the domain aggregate, so future changes to {@code OidcClient} do not
 * leak onto the API.
 *
 * <p>The JSON is intentionally identical to what serializing the domain aggregate produced before:
 * value-object fields ({@code id}, {@code clientId}, {@code clientName}, {@code redirectUris},
 * {@code scopes}, ...) are emitted as {@code { "value": ... }}, while grant types and
 * authentication methods are flat strings. Consumers (the UI) already depend on this shape.
 */
public record OidcClientResponse(
    Value id,
    Value clientId,
    Value clientName,
    Set<String> grantTypes,
    Set<String> authenticationMethods,
    Set<Value> redirectUris,
    Set<Value> postLogoutRedirectUris,
    Set<Value> scopes,
    TokenSettingsResponse tokenSettings,
    ClientSettingsResponse clientSettings,
    Instant clientIdIssuedAt
) {

  /** Mirrors how a single-value value object serialized: {@code { "value": ... }}. */
  public record Value(String value) {}

  public record TokenSettingsResponse(
      Duration accessTokenTimeToLive,
      Duration refreshTokenTimeToLive,
      Duration authorizationCodeTimeToLive,
      boolean reuseRefreshTokens
  ) {}

  public record ClientSettingsResponse(
      boolean requireAuthorizationConsent,
      boolean requireProofKey
  ) {}

  public static OidcClientResponse from(OidcClient client) {
    var tokenSettings = client.getTokenSettings();
    var clientSettings = client.getClientSettings();

    return new OidcClientResponse(
        new Value(client.getId().getValue().toString()),
        new Value(client.getClientId().getValue()),
        new Value(client.getClientName().getValue()),
        client.getGrantTypes().stream()
            .map(AuthorizationGrantType::getValue)
            .collect(Collectors.toSet()),
        client.getAuthenticationMethods().stream()
            .map(ClientAuthenticationMethod::getValue)
            .collect(Collectors.toSet()),
        client.getRedirectUris().stream()
            .map(OidcClientResponse::toValue)
            .collect(Collectors.toSet()),
        client.getPostLogoutRedirectUris().stream()
            .map(OidcClientResponse::toValue)
            .collect(Collectors.toSet()),
        client.getScopes().stream()
            .map(scope -> new Value(scope.getValue()))
            .collect(Collectors.toSet()),
        new TokenSettingsResponse(
            tokenSettings.getAccessTokenTimeToLive(),
            tokenSettings.getRefreshTokenTimeToLive(),
            tokenSettings.getAuthorizationCodeTimeToLive(),
            tokenSettings.isReuseRefreshTokens()
        ),
        new ClientSettingsResponse(
            clientSettings.isRequireAuthorizationConsent(),
            clientSettings.isRequireProofKey()
        ),
        client.getClientIdIssuedAt()
    );
  }

  private static Value toValue(RedirectUri uri) {
    return new Value(uri.getValue());
  }
}
