package com.hjusic.auth.domain.oidc.infrastructure;

import com.hjusic.auth.domain.oidc.model.AuthorizationGrantType;
import com.hjusic.auth.domain.oidc.model.ClientAuthenticationMethod;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.valueObjects.*;

import java.time.Duration;
import java.util.stream.Collectors;

public class OidcClientMapper {

  private OidcClientMapper() {}

  public static OidcClient toDomain(OidcClientDatabaseEntity entity) {
    return OidcClient.builder()
        .id(OAuthClientId.of(entity.getId()).get())
        .clientId(ClientId.of(entity.getClientId()).get())
        .clientSecret(ClientSecret.fromEncoded(entity.getClientSecret()))
        .clientName(ClientName.of(entity.getClientName()).get())
        .grantTypes(
            entity.getGrantTypes().stream()
                .map(s -> AuthorizationGrantType.of(s).get())
                .collect(Collectors.toSet())
        )
        .authenticationMethods(
            entity.getAuthenticationMethods().stream()
                .map(m -> ClientAuthenticationMethod.of(m).get())
                .collect(Collectors.toSet())
        )
        .redirectUris(
            entity.getRedirectUris().stream()
                .map(uri -> RedirectUri.of(uri).get())
                .collect(Collectors.toSet())
        )
        .postLogoutRedirectUris(
            entity.getPostLogoutRedirectUris().stream()
                .map(uri -> RedirectUri.of(uri).get())
                .collect(Collectors.toSet())
        )
        .scopes(
            entity.getScopes().stream()
                .map(scope -> Scope.of(scope).get())
                .collect(Collectors.toSet())
        )
        .tokenSettings(TokenSettings.builder()
            .accessTokenTimeToLive(Duration.ofSeconds(entity.getAccessTokenTimeToLiveSeconds()))
            .refreshTokenTimeToLive(Duration.ofSeconds(entity.getRefreshTokenTimeToLiveSeconds()))
            .authorizationCodeTimeToLive(Duration.ofSeconds(entity.getAuthorizationCodeTimeToLiveSeconds()))
            .reuseRefreshTokens(entity.getReuseRefreshTokens())
            .build())
        .clientSettings(ClientSettings.builder()
            .requireProofKey(entity.getRequireProofKey())
            .requireAuthorizationConsent(entity.getRequireAuthorizationConsent())
            .build())
        .clientIdIssuedAt(entity.getClientIdIssuedAt())
        .build();
  }

  public static OidcClientDatabaseEntity toEntity(OidcClient domain) {
    return OidcClientDatabaseEntity.builder()
        .id(domain.getId().getValue().toString())
        .clientId(domain.getClientId().getValue())
        .clientSecret(domain.getClientSecret().getEncodedValue())
        .clientName(domain.getClientName().getValue())
        .grantTypes(
            domain.getGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet())
        )
        .authenticationMethods(
            domain.getAuthenticationMethods().stream()
                .map(ClientAuthenticationMethod::getValue)
                .collect(Collectors.toSet())
        )
        .redirectUris(
            domain.getRedirectUris().stream()
                .map(RedirectUri::getValue)
                .collect(Collectors.toSet())
        )
        .postLogoutRedirectUris(
            domain.getPostLogoutRedirectUris().stream()
                .map(RedirectUri::getValue)
                .collect(Collectors.toSet())
        )
        .scopes(
            domain.getScopes().stream()
                .map(Scope::getValue)
                .collect(Collectors.toSet())
        )
        .accessTokenTimeToLiveSeconds(domain.getTokenSettings().getAccessTokenTimeToLive().toSeconds())
        .refreshTokenTimeToLiveSeconds(domain.getTokenSettings().getRefreshTokenTimeToLive().toSeconds())
        .authorizationCodeTimeToLiveSeconds(domain.getTokenSettings().getAuthorizationCodeTimeToLive().toSeconds())
        .reuseRefreshTokens(domain.getTokenSettings().isReuseRefreshTokens())
        .requireProofKey(domain.getClientSettings().isRequireProofKey())
        .requireAuthorizationConsent(domain.getClientSettings().isRequireAuthorizationConsent())
        .clientIdIssuedAt(domain.getClientIdIssuedAt())
        .build();
  }

  public static void updateEntity(OidcClientDatabaseEntity entity, OidcClient domain) {
    entity.setClientName(domain.getClientName().getValue());
    entity.setClientSecret(domain.getClientSecret().getEncodedValue());
    entity.setGrantTypes(
        domain.getGrantTypes().stream()
            .map(AuthorizationGrantType::getValue)
            .collect(Collectors.toSet())
    );
    entity.setRedirectUris(
        domain.getRedirectUris().stream()
            .map(RedirectUri::getValue)
            .collect(Collectors.toSet())
    );
    entity.setPostLogoutRedirectUris(
        domain.getPostLogoutRedirectUris().stream()
            .map(RedirectUri::getValue)
            .collect(Collectors.toSet())
    );
    entity.setScopes(
        domain.getScopes().stream()
            .map(Scope::getValue)
            .collect(Collectors.toSet())
    );
    entity.setAccessTokenTimeToLiveSeconds(domain.getTokenSettings().getAccessTokenTimeToLive().toSeconds());
    entity.setRefreshTokenTimeToLiveSeconds(domain.getTokenSettings().getRefreshTokenTimeToLive().toSeconds());
    entity.setAuthorizationCodeTimeToLiveSeconds(domain.getTokenSettings().getAuthorizationCodeTimeToLive().toSeconds());
    entity.setReuseRefreshTokens(domain.getTokenSettings().isReuseRefreshTokens());
    entity.setRequireProofKey(domain.getClientSettings().isRequireProofKey());
    entity.setRequireAuthorizationConsent(domain.getClientSettings().isRequireAuthorizationConsent());
  }
}