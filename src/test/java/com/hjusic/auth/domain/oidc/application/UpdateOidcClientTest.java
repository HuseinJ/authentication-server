package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientUpdatedEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientName;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import io.vavr.control.Option;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UpdateOidcClientTest {

  @Mock
  private OidcClients clients;

  @InjectMocks
  private UpdateOidcClient updateOidcClient;

  private String validId;
  private String clientName;
  private Set<String> grantTypes;
  private Set<String> redirectUris;
  private Set<String> postLogoutRedirectUris;
  private Set<String> scopes;
  private TokenSettings tokenSettings;
  private ClientSettings clientSettings;
  private OidcClient existingClient;
  private OAuthClientUpdatedEvent updatedEvent;

  @BeforeEach
  void setUp() {
    validId = "550e8400-e29b-41d4-a716-446655440000";
    clientName = "Updated Client";
    grantTypes = Set.of("authorization_code");
    redirectUris = Set.of("https://example.com/callback");
    postLogoutRedirectUris = Set.of("https://example.com/logout");
    scopes = Set.of("openid", "profile");
    tokenSettings = TokenSettings.defaults();
    clientSettings = ClientSettings.defaults();
    existingClient = mock(OidcClient.class);
    updatedEvent = mock(OAuthClientUpdatedEvent.class);
  }

  @Nested
  class SuccessfulUpdate {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
      when(existingClient.update(
          any(ClientName.class),
          anySet(),
          anySet(),
          anySet(),
          anySet(),
          any(TokenSettings.class),
          any(ClientSettings.class)
      )).thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);
    }

    @Test
    void shouldUpdateClientSuccessfully() {
      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(existingClient);
    }

    @Test
    void shouldLookUpClientById() {
      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      var idCaptor = ArgumentCaptor.forClass(OAuthClientId.class);
      verify(clients).findById(idCaptor.capture());
      assertThat(idCaptor.getValue().getValue().toString()).isEqualTo(validId);
    }

    @Test
    void shouldCallUpdateOnClient() {
      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      verify(existingClient).update(
          any(ClientName.class),
          anySet(),
          anySet(),
          anySet(),
          anySet(),
          eq(tokenSettings),
          eq(clientSettings));
    }

    @Test
    void shouldPassValidatedClientNameToUpdate() {
      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      var clientNameCaptor = ArgumentCaptor.forClass(ClientName.class);
      verify(existingClient).update(
          clientNameCaptor.capture(),
          anySet(), anySet(), anySet(), anySet(),
          any(TokenSettings.class), any(ClientSettings.class));

      assertThat(clientNameCaptor.getValue().getValue()).isEqualTo(clientName);
    }

    @Test
    void shouldPassValidatedGrantTypesToUpdate() {
      var multipleGrantTypes = Set.of("authorization_code", "refresh_token");

      updateOidcClient.update(
          validId, clientName, multipleGrantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      @SuppressWarnings("unchecked")
      var grantTypesCaptor = ArgumentCaptor.forClass(Set.class);
      verify(existingClient).update(
          any(ClientName.class),
          grantTypesCaptor.capture(),
          anySet(), anySet(), anySet(),
          any(TokenSettings.class), any(ClientSettings.class));

      assertThat(grantTypesCaptor.getValue()).hasSize(2);
    }

    @Test
    void shouldTriggerUpdatedEvent() {
      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      verify(clients).trigger(updatedEvent);
    }

    @Test
    void shouldReturnUpdatedClient() {
      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.get()).isEqualTo(existingClient);
    }
  }

  @Nested
  class IdValidation {

    @Test
    void shouldFailWhenIdIsNull() {
      var result = updateOidcClient.update(
          null, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsEmpty() {
      var result = updateOidcClient.update(
          "", clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsBlank() {
      var result = updateOidcClient.update(
          "   ", clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsInvalidFormat() {
      var result = updateOidcClient.update(
          "not-a-valid-uuid", clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }
  }

  @Nested
  class ClientNotFound {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenClientDoesNotExist() {
      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    void shouldReturnClientNotFoundError() {
      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientNotFound(validId));
    }

    @Test
    void shouldNotTriggerEventWhenClientNotFound() {
      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      verify(clients, never()).trigger(any(OAuthClientUpdatedEvent.class));
    }
  }

  @Nested
  class ClientNameValidation {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
    }

    @Test
    void shouldFailWhenClientNameIsNull() {
      var result = updateOidcClient.update(
          validId, null, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientNameIsEmpty() {
      var result = updateOidcClient.update(
          validId, "", grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientNameIsBlank() {
      var result = updateOidcClient.update(
          validId, "   ", grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }
  }

  @Nested
  class GrantTypesValidation {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
    }

    @Test
    void shouldFailWhenGrantTypesContainsInvalidValue() {
      var invalidGrantTypes = Set.of("invalid_grant_type");

      var result = updateOidcClient.update(
          validId, clientName, invalidGrantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenGrantTypesIsEmpty() {
      var result = updateOidcClient.update(
          validId, clientName, Set.of(), redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptValidGrantTypes() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var validGrantTypes = Set.of("authorization_code", "refresh_token", "client_credentials");

      var result = updateOidcClient.update(
          validId, clientName, validGrantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class RedirectUrisValidation {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
    }

    @Test
    void shouldFailWhenRedirectUriIsInvalid() {
      var invalidRedirectUris = Set.of("not-a-valid-uri");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, invalidRedirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenRedirectUriUsesHttpForNonLocalhost() {
      var httpRedirectUri = Set.of("http://example.com/callback");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, httpRedirectUri,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptHttpsRedirectUri() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var httpsRedirectUri = Set.of("https://example.com/callback");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, httpsRedirectUri,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptLocalhostHttpRedirectUri() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var localhostRedirectUri = Set.of("http://localhost:8080/callback");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, localhostRedirectUri,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptMultipleRedirectUris() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var multipleRedirectUris = Set.of(
          "https://example.com/callback",
          "https://example.com/callback2",
          "http://localhost:3000/callback");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, multipleRedirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class PostLogoutRedirectUrisValidation {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
    }

    @Test
    void shouldFailWhenPostLogoutRedirectUriIsInvalid() {
      var invalidPostLogoutUris = Set.of("not-a-valid-uri");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          invalidPostLogoutUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenPostLogoutUriUsesHttpForNonLocalhost() {
      var httpPostLogoutUri = Set.of("http://example.com/logout");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          httpPostLogoutUri, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptValidPostLogoutRedirectUris() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var validPostLogoutUris = Set.of("https://example.com/logout");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          validPostLogoutUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class ScopesValidation {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
    }

    @Test
    void shouldFailWhenScopeIsInvalid() {
      var invalidScopes = Set.of("invalid scope with spaces");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, invalidScopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptStandardOidcScopes() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var standardScopes = Set.of("openid", "profile", "email", "address", "phone");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, standardScopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptCustomScopes() {
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);

      var customScopes = Set.of("openid", "custom:read", "custom:write");

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, customScopes, tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class ValidationOrder {

    @Test
    void shouldValidateIdBeforeLookingUpClient() {
      var result = updateOidcClient.update(
          "invalid-uuid", clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
    }

    @Test
    void shouldLookUpClientBeforeValidatingOtherFields() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.empty());

      var result = updateOidcClient.update(
          validId, null, Set.of("invalid"), Set.of("invalid"),
          Set.of("invalid"), Set.of("invalid scope"), tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientNotFound(validId));
    }

    @Test
    void shouldValidateClientNameBeforeGrantTypes() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));

      var result = updateOidcClient.update(
          validId, "", Set.of("invalid_grant"), redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(existingClient, never()).update(any(), anySet(), anySet(), anySet(), anySet(), any(), any());
    }

    @Test
    void shouldValidateGrantTypesBeforeRedirectUris() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));

      var result = updateOidcClient.update(
          validId, clientName, Set.of("invalid_grant"), Set.of("invalid-uri"),
          postLogoutRedirectUris, scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    void shouldValidateRedirectUrisBeforePostLogoutUris() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, Set.of("invalid-uri"),
          Set.of("another-invalid-uri"), scopes, tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    void shouldValidatePostLogoutUrisBeforeScopes() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));

      var result = updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          Set.of("invalid-uri"), Set.of("invalid scope"), tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
    }
  }

  @Nested
  class TokenAndClientSettings {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
      when(existingClient.update(any(), anySet(), anySet(), anySet(), anySet(), any(), any()))
          .thenReturn(updatedEvent);
      when(clients.trigger(any(OAuthClientUpdatedEvent.class))).thenReturn(existingClient);
    }

    @Test
    void shouldPassTokenSettingsToUpdate() {
      var customTokenSettings = TokenSettings.builder()
          .accessTokenTimeToLive(Duration.ofSeconds(7200))
          .build();

      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, customTokenSettings, clientSettings);

      verify(existingClient).update(
          any(), anySet(), anySet(), anySet(), anySet(),
          eq(customTokenSettings), any(ClientSettings.class));
    }

    @Test
    void shouldPassClientSettingsToUpdate() {
      var customClientSettings = ClientSettings.builder()
          .requireProofKey(true)
          .build();

      updateOidcClient.update(
          validId, clientName, grantTypes, redirectUris,
          postLogoutRedirectUris, scopes, tokenSettings, customClientSettings);

      verify(existingClient).update(
          any(), anySet(), anySet(), anySet(), anySet(),
          any(TokenSettings.class), eq(customClientSettings));
    }
  }
}