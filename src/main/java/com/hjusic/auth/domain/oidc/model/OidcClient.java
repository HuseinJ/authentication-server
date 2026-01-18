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
import lombok.*;

import java.time.Instant;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;

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

    this.clientName = clientName;
    this.grantTypes = grantTypes;
    this.redirectUris = redirectUris;
    this.postLogoutRedirectUris = postLogoutRedirectUris;
    this.scopes = scopes;
    this.tokenSettings = tokenSettings;
    this.clientSettings = clientSettings;

    return OAuthClientUpdatedEvent.of(this);
  }

  public OAuthClientSecretRegeneratedEvent regenerateSecret(PasswordEncoder passwordEncoder) {
    this.clientSecret = ClientSecret.generate(passwordEncoder);
    return OAuthClientSecretRegeneratedEvent.of(this, clientSecret);
  }

  public OAuthClientDeletedEvent delete() {
    return OAuthClientDeletedEvent.of(this);
  }
}