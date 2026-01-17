package com.hjusic.auth.domain.oidc.model;

import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientName;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSecret;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import com.hjusic.auth.domain.oidc.model.valueObjects.Scope;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import java.time.Duration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Set;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OAuthClientTest {

  private ClientId clientId;
  private ClientName clientName;
  private ClientSecret clientSecret;
  private Set<AuthorizationGrantType> grantTypes;
  private Set<ClientAuthenticationMethod> authenticationMethods;
  private Set<RedirectUri> redirectUris;
  private Set<RedirectUri> postLogoutRedirectUris;
  private Set<Scope> scopes;
  private TokenSettings tokenSettings;
  private ClientSettings clientSettings;

  @BeforeEach
  void setUp() {
    clientId = ClientId.of("test-client").get();
    clientName = ClientName.of("Test Client").get();
    var passwordEncoder = mock(PasswordEncoder.class);
    when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
    clientSecret = ClientSecret.generate(passwordEncoder);
    grantTypes = Set.of(AuthorizationGrantType.AUTHORIZATION_CODE);
    authenticationMethods = Set.of(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    redirectUris = Set.of(RedirectUri.of("https://example.com/callback").get());
    postLogoutRedirectUris = Set.of(RedirectUri.of("https://example.com/logout").get());
    scopes = Set.of(Scope.of("openid").get(), Scope.of("profile").get());
    tokenSettings = TokenSettings.defaults();
    clientSettings = ClientSettings.defaults();
  }

  @Nested
  class Create {

    @Test
    void shouldCreateClientWithGeneratedId() {
      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      assertThat(event.getClient().getId()).isNotNull();
    }

    @Test
    void shouldCreateClientWithProvidedValues() {
      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      var client = event.getClient();
      assertThat(client.getClientId()).isEqualTo(clientId);
      assertThat(client.getClientName()).isEqualTo(clientName);
      assertThat(client.getClientSecret()).isEqualTo(clientSecret);
      assertThat(client.getGrantTypes()).isEqualTo(grantTypes);
      assertThat(client.getAuthenticationMethods()).isEqualTo(authenticationMethods);
      assertThat(client.getRedirectUris()).isEqualTo(redirectUris);
      assertThat(client.getPostLogoutRedirectUris()).isEqualTo(postLogoutRedirectUris);
      assertThat(client.getScopes()).isEqualTo(scopes);
      assertThat(client.getTokenSettings()).isEqualTo(tokenSettings);
      assertThat(client.getClientSettings()).isEqualTo(clientSettings);
    }

    @Test
    void shouldSetClientIdIssuedAtToCurrentTime() {
      var before = Instant.now();

      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      var after = Instant.now();
      var issuedAt = event.getClient().getClientIdIssuedAt();

      assertThat(issuedAt).isAfterOrEqualTo(before);
      assertThat(issuedAt).isBeforeOrEqualTo(after);
    }

    @Test
    void shouldReturnEventWithPlainTextSecret() {
      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      assertThat(event.getPlainTextSecret()).isEqualTo(clientSecret.getPlainText());
    }

    @Test
    void shouldGenerateUniqueIdsForDifferentClients() {
      var event1 = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");

      var event2 = OidcClient.create(
          ClientId.of("another-client").get(), clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, ClientSecret.generate(passwordEncoder));

      assertThat(event1.getClient().getId()).isNotEqualTo(event2.getClient().getId());
    }
  }

  @Nested
  class Update {

    private OidcClient existingClient;

    @BeforeEach
    void setUp() {
      var createEvent = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);
      existingClient = createEvent.getClient();
    }

    @Test
    void shouldUpdateClientName() {
      var newClientName = ClientName.of("Updated Client Name").get();

      var event = existingClient.update(
          newClientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(event.getClient().getClientName()).isEqualTo(newClientName);
    }

    @Test
    void shouldUpdateGrantTypes() {
      var newGrantTypes = Set.of(
          AuthorizationGrantType.AUTHORIZATION_CODE,
          AuthorizationGrantType.REFRESH_TOKEN);

      var event = existingClient.update(
          clientName, newGrantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(event.getClient().getGrantTypes()).isEqualTo(newGrantTypes);
    }

    @Test
    void shouldUpdateRedirectUris() {
      var newRedirectUris = Set.of(
          RedirectUri.of("https://newexample.com/callback").get(),
          RedirectUri.of("https://newexample.com/callback2").get());

      var event = existingClient.update(
          clientName, grantTypes, newRedirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(event.getClient().getRedirectUris()).isEqualTo(newRedirectUris);
    }

    @Test
    void shouldUpdatePostLogoutRedirectUris() {
      var newPostLogoutUris = Set.of(
          RedirectUri.of("https://newexample.com/logout").get());

      var event = existingClient.update(
          clientName, grantTypes, redirectUris,
          newPostLogoutUris, scopes, tokenSettings, clientSettings);

      assertThat(event.getClient().getPostLogoutRedirectUris()).isEqualTo(newPostLogoutUris);
    }

    @Test
    void shouldUpdateScopes() {
      var newScopes = Set.of(
          Scope.of("openid").get(),
          Scope.of("email").get(),
          Scope.of("address").get());

      var event = existingClient.update(
          clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, newScopes, tokenSettings, clientSettings);

      assertThat(event.getClient().getScopes()).isEqualTo(newScopes);
    }

    @Test
    void shouldUpdateTokenSettings() {
      var newTokenSettings = TokenSettings.builder()
          .accessTokenTimeToLive(Duration.ofSeconds(7200))
          .build();

      var event = existingClient.update(
          clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, newTokenSettings, clientSettings);

      assertThat(event.getClient().getTokenSettings()).isEqualTo(newTokenSettings);
    }

    @Test
    void shouldUpdateClientSettings() {
      var newClientSettings = ClientSettings.builder()
          .requireProofKey(true)
          .build();

      var event = existingClient.update(
          clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, newClientSettings);

      assertThat(event.getClient().getClientSettings()).isEqualTo(newClientSettings);
    }

    @Test
    void shouldPreserveImmutableFields() {
      var originalId = existingClient.getId();
      var originalClientId = existingClient.getClientId();
      var originalClientSecret = existingClient.getClientSecret();
      var originalIssuedAt = existingClient.getClientIdIssuedAt();
      var originalAuthMethods = existingClient.getAuthenticationMethods();

      existingClient.update(
          ClientName.of("New Name").get(),
          Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS),
          Set.of(RedirectUri.of("https://new.com/callback").get()),
          Set.of(RedirectUri.of("https://new.com/logout").get()),
          Set.of(Scope.of("email").get()),
          tokenSettings,
          clientSettings);

      assertThat(existingClient.getId()).isEqualTo(originalId);
      assertThat(existingClient.getClientId()).isEqualTo(originalClientId);
      assertThat(existingClient.getClientSecret()).isEqualTo(originalClientSecret);
      assertThat(existingClient.getClientIdIssuedAt()).isEqualTo(originalIssuedAt);
      assertThat(existingClient.getAuthenticationMethods()).isEqualTo(originalAuthMethods);
    }

    @Test
    void shouldReturnEventWithUpdatedClient() {
      var newClientName = ClientName.of("Updated Name").get();

      var event = existingClient.update(
          newClientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(event.getClient()).isEqualTo(existingClient);
    }
  }

  @Nested
  class RegenerateSecret {

    private OidcClient existingClient;

    @BeforeEach
    void setUp() {
      var createEvent = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);
      existingClient = createEvent.getClient();
    }

    @Test
    void shouldGenerateNewSecret() {
      var originalSecret = existingClient.getClientSecret();

      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      existingClient.regenerateSecret(passwordEncoder);

      assertThat(existingClient.getClientSecret()).isNotEqualTo(originalSecret);
    }

    @Test
    void shouldReturnEventWithPlainTextSecret() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      var event = existingClient.regenerateSecret(passwordEncoder);

      assertThat(event.getNewClientSecret().getPlainText()).isNotNull();
      assertThat(event.getNewClientSecret().getPlainText()).isNotBlank();
    }

    @Test
    void shouldReturnEventWithUpdatedClient() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      var event = existingClient.regenerateSecret(passwordEncoder);

      assertThat(event.getClient()).isEqualTo(existingClient);
      assertThat(event.getClient().getClientSecret()).isEqualTo(existingClient.getClientSecret());
    }

    @Test
    void shouldPreserveOtherFields() {
      var originalId = existingClient.getId();
      var originalClientId = existingClient.getClientId();
      var originalClientName = existingClient.getClientName();
      var originalGrantTypes = existingClient.getGrantTypes();

      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      existingClient.regenerateSecret(passwordEncoder);

      assertThat(existingClient.getId()).isEqualTo(originalId);
      assertThat(existingClient.getClientId()).isEqualTo(originalClientId);
      assertThat(existingClient.getClientName()).isEqualTo(originalClientName);
      assertThat(existingClient.getGrantTypes()).isEqualTo(originalGrantTypes);
    }

    @Test
    void shouldGenerateDifferentSecretOnEachCall() {
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      var event1 = existingClient.regenerateSecret(passwordEncoder);
      var secret1 = event1.getNewClientSecret().getPlainText();

      var event2 = existingClient.regenerateSecret(passwordEncoder);
      var secret2 = event2.getNewClientSecret().getPlainText();

      assertThat(secret1).isNotEqualTo(secret2);
    }
  }

  @Nested
  class Delete {

    private OidcClient existingClient;

    @BeforeEach
    void setUp() {
      var createEvent = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);
      existingClient = createEvent.getClient();
    }

    @Test
    void shouldReturnDeleteEventWithClient() {
      var event = existingClient.delete();

      assertThat(event.getClient()).isEqualTo(existingClient);
    }

    @Test
    void shouldReturnEventWithCorrectClientId() {
      var event = existingClient.delete();

      assertThat(event.getClient().getId()).isEqualTo(existingClient.getId());
      assertThat(event.getClient().getClientId()).isEqualTo(existingClient.getClientId());
    }
  }

  @Nested
  class Equality {

    @Test
    void shouldBeEqualWhenIdsMatch() {
      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      var client1 = event.getClient();
      var client2 = event.getClient();

      assertThat(client1).isEqualTo(client2);
    }

    @Test
    void shouldNotBeEqualWhenIdsDiffer() {
      var event1 = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);
      var passwordEncoder = mock(PasswordEncoder.class);
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");

      var event2 = OidcClient.create(
          ClientId.of("different-client").get(), clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, ClientSecret.generate(passwordEncoder));

      assertThat(event1.getClient()).isNotEqualTo(event2.getClient());
    }

    @Test
    void shouldHaveSameHashCodeWhenEqual() {
      var event = OidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings, clientSecret);

      var client = event.getClient();

      assertThat(client.hashCode()).isEqualTo(client.hashCode());
    }
  }
}