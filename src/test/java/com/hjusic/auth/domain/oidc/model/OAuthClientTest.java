package com.hjusic.auth.domain.oidc.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.hjusic.auth.domain.oidc.model.events.OAuthClientCreatedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientDeletedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientSecretRegeneratedEvent;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientUpdatedEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.*;
import io.vavr.control.Either;
import io.vavr.control.Option;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

class OAuthClientTest {

  private OidcClients clients;

  @BeforeEach
  void setUp() {
    clients = mock(OidcClients.class);
    when(clients.findByClientId(anyString())).thenReturn(Option.none());
  }

  @Nested
  @DisplayName("OAuth Client creation")
  class OAuthClientCreationTests {

    @Test
    @DisplayName("Should create OAuth client with valid parameters")
    void shouldCreateOAuthClientWithValidParameters() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "my-client-app",
          "My Application",
          Set.of("authorization_code", "refresh_token"),
          Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"),
          Set.of("http://localhost:8080/logout"),
          Set.of("openid", "profile", "email"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isRight()).isTrue();

      OAuthClientCreatedEvent event = result.get();
      assertThat(event.getClient()).isNotNull();
      assertThat(event.getClient().getClientId().getValue()).isEqualTo("my-client-app");
      assertThat(event.getClient().getClientName().getValue()).isEqualTo("My Application");
      assertThat(event.getPlainTextSecret()).isNotBlank();
    }

    @Test
    @DisplayName("Should create OAuth client with minimal OIDC scopes")
    void shouldCreateOAuthClientWithMinimalOidcScopes() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "oidc-client",
          "OIDC Client",
          Set.of("authorization_code"),
          Set.of("client_secret_basic"),
          Set.of("https://example.com/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getClient().getScopes())
          .extracting(Scope::getValue)
          .containsExactly("openid");
    }

    @Test
    @DisplayName("Should fail when client ID already exists")
    void shouldFailWhenClientIdAlreadyExists() {
      when(clients.findByClientId("existing-client")).thenReturn(Option.of(mock(OidcClient.class)));

      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "existing-client",
          "Existing Client",
          Set.of("authorization_code"),
          Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getCode()).isEqualTo(OAuthClientErrorCode.CLIENT_ALREADY_EXISTS);
    }

    @Test
    @DisplayName("Should fail with invalid client ID")
    void shouldFailWithInvalidClientId() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "ab",  // Too short
          "My Application",
          Set.of("authorization_code"),
          Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getCode()).isEqualTo(OAuthClientErrorCode.VALIDATION_FAILED);
    }

    @Test
    @DisplayName("Should fail with empty grant types")
    void shouldFailWithEmptyGrantTypes() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "my-client",
          "My Application",
          Set.of(),  // Empty grant types
          Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("At least one grant type is required");
    }

    @Test
    @DisplayName("Should fail with invalid redirect URI")
    void shouldFailWithInvalidRedirectUri() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result = OidcClient.create(
          "my-client",
          "My Application",
          Set.of("authorization_code"),
          Set.of("client_secret_basic"),
          Set.of("not-a-valid-uri"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults(),
          clients
      );

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    @DisplayName("Should generate unique client ID for each creation")
    void shouldGenerateUniqueClientId() {
      Either<OAuthClientError, OAuthClientCreatedEvent> result1 = OidcClient.create(
          "client-1", "Client 1",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost/cb1"), Set.of(), Set.of("openid"),
          TokenSettings.defaults(), ClientSettings.defaults(), clients
      );

      Either<OAuthClientError, OAuthClientCreatedEvent> result2 = OidcClient.create(
          "client-2", "Client 2",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost/cb2"), Set.of(), Set.of("openid"),
          TokenSettings.defaults(), ClientSettings.defaults(), clients
      );

      assertThat(result1.get().getClient().getId())
          .isNotEqualTo(result2.get().getClient().getId());
    }
  }

  @Nested
  @DisplayName("OAuth Client update")
  class OAuthClientUpdateTests {

    private OidcClient existingClient;

    @BeforeEach
    void setUp() {
      var createResult = OidcClient.create(
          "test-client", "Test Client",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"), Set.of(),
          Set.of("openid"), TokenSettings.defaults(), ClientSettings.defaults(),
          clients
      );
      existingClient = createResult.get().getClient();
    }

    @Test
    @DisplayName("Should update client name")
    void shouldUpdateClientName() {
      Either<OAuthClientError, OAuthClientUpdatedEvent> result = existingClient.update(
          "Updated Client Name",
          Set.of("authorization_code"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults()
      );

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getClient().getClientName().getValue())
          .isEqualTo("Updated Client Name");
    }

    @Test
    @DisplayName("Should update redirect URIs")
    void shouldUpdateRedirectUris() {
      Either<OAuthClientError, OAuthClientUpdatedEvent> result = existingClient.update(
          "Test Client",
          Set.of("authorization_code"),
          Set.of("https://new-domain.com/callback", "https://another.com/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults()
      );

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getClient().getRedirectUris()).hasSize(2);
    }

    @Test
    @DisplayName("Should update scopes")
    void shouldUpdateScopes() {
      Either<OAuthClientError, OAuthClientUpdatedEvent> result = existingClient.update(
          "Test Client",
          Set.of("authorization_code"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid", "profile", "email", "custom:scope"),
          TokenSettings.defaults(),
          ClientSettings.defaults()
      );

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getClient().getScopes()).hasSize(4);
    }

    @Test
    @DisplayName("Should fail update with invalid client name")
    void shouldFailUpdateWithInvalidClientName() {
      Either<OAuthClientError, OAuthClientUpdatedEvent> result = existingClient.update(
          "",  // Invalid empty name
          Set.of("authorization_code"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults()
      );

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Client name cannot be empty");
    }

    @Test
    @DisplayName("Should not change client ID on update")
    void shouldNotChangeClientIdOnUpdate() {
      String originalClientId = existingClient.getClientId().getValue();

      Either<OAuthClientError, OAuthClientUpdatedEvent> result = existingClient.update(
          "New Name",
          Set.of("authorization_code"),
          Set.of("http://localhost:8080/callback"),
          Set.of(),
          Set.of("openid"),
          TokenSettings.defaults(),
          ClientSettings.defaults()
      );

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getClient().getClientId().getValue()).isEqualTo(originalClientId);
    }
  }

  @Nested
  @DisplayName("OAuth Client secret regeneration")
  class OAuthClientSecretRegenerationTests {

    @Test
    @DisplayName("Should regenerate client secret")
    void shouldRegenerateClientSecret() {
      var createResult = OidcClient.create(
          "test-client", "Test Client",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"), Set.of(),
          Set.of("openid"), TokenSettings.defaults(), ClientSettings.defaults(),
          clients
      );
      OidcClient client = createResult.get().getClient();
      String originalSecret = createResult.get().getPlainTextSecret();

      OAuthClientSecretRegeneratedEvent event = client.regenerateSecret();

      assertThat(event.getPlainTextSecret()).isNotBlank();
      assertThat(event.getPlainTextSecret()).isNotEqualTo(originalSecret);
      assertThat(event.getClient()).isEqualTo(client);
    }

    @Test
    @DisplayName("Should update client with new secret")
    void shouldUpdateClientWithNewSecret() {
      var createResult = OidcClient.create(
          "test-client", "Test Client",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"), Set.of(),
          Set.of("openid"), TokenSettings.defaults(), ClientSettings.defaults(),
          clients
      );
      OidcClient client = createResult.get().getClient();
      ClientSecret originalClientSecret = client.getClientSecret();

      client.regenerateSecret();

      assertThat(client.getClientSecret()).isNotEqualTo(originalClientSecret);
    }
  }

  @Nested
  @DisplayName("OAuth Client deletion")
  class OAuthClientDeletionTests {

    @Test
    @DisplayName("Should create deletion event")
    void shouldCreateDeletionEvent() {
      var createResult = OidcClient.create(
          "test-client", "Test Client",
          Set.of("authorization_code"), Set.of("client_secret_basic"),
          Set.of("http://localhost:8080/callback"), Set.of(),
          Set.of("openid"), TokenSettings.defaults(), ClientSettings.defaults(),
          clients
      );
      OidcClient client = createResult.get().getClient();

      OAuthClientDeletedEvent event = client.delete();

      assertThat(event.getClient().getId()).isEqualTo(client.getId());
      assertThat(event.getClient().getClientId()).isEqualTo(client.getClientId());
    }
  }
}