package com.hjusic.auth.domain.oidc.infrastructure;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

  private final OidcClientDatabaseRepository oidcClientJpaRepository;
  private final PasswordEncoder passwordEncoder;

  @Override
  public void save(RegisteredClient registeredClient) {
    // Not used - we manage clients through our own API
    throw new UnsupportedOperationException("Use OidcClient API to manage clients");
  }

  @Override
  public RegisteredClient findById(String id) {
    return oidcClientJpaRepository.findById(id)
        .map(this::toRegisteredClient)
        .orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    return oidcClientJpaRepository.findByClientId(clientId)
        .map(this::toRegisteredClient)
        .orElse(null);
  }

  private RegisteredClient toRegisteredClient(OidcClientDatabaseEntity entity) {
    var builder = RegisteredClient.withId(entity.getId())
        .clientId(entity.getClientId())
        .clientSecret(entity.getClientSecret())
        .clientName(entity.getClientName())
        .clientIdIssuedAt(entity.getClientIdIssuedAt());

    // Map grant types
    entity.getGrantTypes().forEach(grantType -> {
      builder.authorizationGrantType(mapGrantType(grantType));
    });

    // Map authentication methods
    entity.getAuthenticationMethods().forEach(method -> {
      builder.clientAuthenticationMethod(mapAuthenticationMethod(method));
    });

    // Map redirect URIs
    entity.getRedirectUris().forEach(builder::redirectUri);

    // Map post logout redirect URIs
    entity.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);

    // Map scopes
    entity.getScopes().forEach(builder::scope);

    // Token settings
    builder.tokenSettings(TokenSettings.builder()
        .accessTokenTimeToLive(Duration.ofSeconds(
            entity.getAccessTokenTimeToLiveSeconds() != null
                ? entity.getAccessTokenTimeToLiveSeconds()
                : 3600))
        .refreshTokenTimeToLive(Duration.ofSeconds(
            entity.getRefreshTokenTimeToLiveSeconds() != null
                ? entity.getRefreshTokenTimeToLiveSeconds()
                : 86400))
        .authorizationCodeTimeToLive(Duration.ofSeconds(
            entity.getAuthorizationCodeTimeToLiveSeconds() != null
                ? entity.getAuthorizationCodeTimeToLiveSeconds()
                : 300))
        .reuseRefreshTokens(entity.getReuseRefreshTokens() != null
            ? entity.getReuseRefreshTokens()
            : false)
        .build());

    // Client settings
    builder.clientSettings(ClientSettings.builder()
        .requireProofKey(entity.getRequireProofKey() != null
            ? entity.getRequireProofKey()
            : false)
        .requireAuthorizationConsent(entity.getRequireAuthorizationConsent() != null
            ? entity.getRequireAuthorizationConsent()
            : true)
        .build());

    return builder.build();
  }

  private AuthorizationGrantType mapGrantType(String grantType) {
    return switch (grantType) {
      case "authorization_code" -> AuthorizationGrantType.AUTHORIZATION_CODE;
      case "refresh_token" -> AuthorizationGrantType.REFRESH_TOKEN;
      case "client_credentials" -> AuthorizationGrantType.CLIENT_CREDENTIALS;
      case "device_code" -> AuthorizationGrantType.DEVICE_CODE;
      case "jwt_bearer" -> AuthorizationGrantType.JWT_BEARER;
      default -> new AuthorizationGrantType(grantType);
    };
  }

  private ClientAuthenticationMethod mapAuthenticationMethod(String method) {
    return switch (method) {
      case "client_secret_basic" -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
      case "client_secret_post" -> ClientAuthenticationMethod.CLIENT_SECRET_POST;
      case "client_secret_jwt" -> ClientAuthenticationMethod.CLIENT_SECRET_JWT;
      case "private_key_jwt" -> ClientAuthenticationMethod.PRIVATE_KEY_JWT;
      case "none" -> ClientAuthenticationMethod.NONE;
      default -> new ClientAuthenticationMethod(method);
    };
  }
}