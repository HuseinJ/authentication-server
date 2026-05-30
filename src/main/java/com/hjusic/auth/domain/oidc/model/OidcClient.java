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
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.time.Instant;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
@Builder(toBuilder = true)
@EqualsAndHashCode(of = {"id"})
public class OidcClient {

  private final OAuthClientId id;
  private final ClientId clientId;
  private final ClientSecret clientSecret;
  private final ClientName clientName;
  private final Set<AuthorizationGrantType> grantTypes;
  private final Set<ClientAuthenticationMethod> authenticationMethods;
  private final Set<RedirectUri> redirectUris;
  private final Set<RedirectUri> postLogoutRedirectUris;
  private final Set<Scope> scopes;
  private final TokenSettings tokenSettings;
  private final ClientSettings clientSettings;
  private final Instant clientIdIssuedAt;

  public static OAuthClientCreatedEvent create(
      ClientId clientId,
      ClientName clientName,
      Set<AuthorizationGrantType> grantTypes,
      Set<ClientAuthenticationMethod> authenticationMethods,
      Set<RedirectUri> redirectUris,
      Set<RedirectUri> postLogoutRedirectUris,
      Set<Scope> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings,
      ClientSecret clientSecret) {

    var client = OidcClient.builder()
        .id(OAuthClientId.generate())
        .clientId(clientId)
        .clientSecret(clientSecret)
        .clientName(clientName)
        .grantTypes(grantTypes)
        .authenticationMethods(authenticationMethods)
        .redirectUris(redirectUris)
        .postLogoutRedirectUris(postLogoutRedirectUris)
        .scopes(scopes)
        .tokenSettings(tokenSettings)
        .clientSettings(clientSettings)
        .clientIdIssuedAt(Instant.now())
        .build();

    return OAuthClientCreatedEvent.of(client, clientSecret.getPlainText());
  }

  public OAuthClientUpdatedEvent update(
      ClientName clientName,
      Set<AuthorizationGrantType> grantTypes,
      Set<RedirectUri> redirectUris,
      Set<RedirectUri> postLogoutRedirectUris,
      Set<Scope> scopes,
      TokenSettings tokenSettings,
      ClientSettings clientSettings) {

    var updated = this.toBuilder()
        .clientName(clientName)
        .grantTypes(grantTypes)
        .redirectUris(redirectUris)
        .postLogoutRedirectUris(postLogoutRedirectUris)
        .scopes(scopes)
        .tokenSettings(tokenSettings)
        .clientSettings(clientSettings)
        .build();

    return OAuthClientUpdatedEvent.of(updated);
  }

  public OAuthClientSecretRegeneratedEvent regenerateSecret(PasswordEncoder passwordEncoder) {
    var newSecret = ClientSecret.generate(passwordEncoder);
    var updated = this.toBuilder().clientSecret(newSecret).build();
    return OAuthClientSecretRegeneratedEvent.of(updated, newSecret);
  }

  public OAuthClientDeletedEvent delete() {
    return OAuthClientDeletedEvent.of(this);
  }
}
