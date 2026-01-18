package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientCreatedEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientId;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSettings;
import com.hjusic.auth.domain.oidc.model.valueObjects.TokenSettings;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CreateOidcClientTest {

  @Mock
  private OidcClients clients;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private CreateOidcClient createOidcClient;

  private String clientId;
  private String clientName;
  private Set<String> grantTypes;
  private Set<String> authenticationMethods;
  private Set<String> redirectUris;
  private Set<String> postLogoutRedirectUris;
  private Set<String> scopes;
  private TokenSettings tokenSettings;
  private ClientSettings clientSettings;

  @BeforeEach
  void setUp() {
    clientId = "test-client";
    clientName = "Test Client";
    grantTypes = Set.of("authorization_code");
    authenticationMethods = Set.of("client_secret_basic");
    redirectUris = Set.of("https://example.com/callback");
    postLogoutRedirectUris = Set.of("https://example.com/logout");
    scopes = Set.of("openid", "profile");
    tokenSettings = TokenSettings.defaults();
    clientSettings = ClientSettings.defaults();
  }

  @Nested
  class SuccessfulCreation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> {
            OAuthClientCreatedEvent event = invocation.getArgument(0);
            return event.getClient();
          });
    }

    @Test
    void shouldCreateClientSuccessfully() {
      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isNotNull();
    }

    @Test
    void shouldReturnClientWithCorrectClientId() {
      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.get().getClientId().getValue()).isEqualTo(clientId);
    }

    @Test
    void shouldReturnClientWithCorrectClientName() {
      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.get().getClientName().getValue()).isEqualTo(clientName);
    }

    @Test
    void shouldCheckIfClientAlreadyExists() {
      createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      verify(clients).findByClientId(any(ClientId.class));
    }

    @Test
    void shouldTriggerCreatedEvent() {
      createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      var eventCaptor = ArgumentCaptor.forClass(OAuthClientCreatedEvent.class);
      verify(clients).trigger(eventCaptor.capture());

      var event = eventCaptor.getValue();
      assertThat(event.getClient().getClientId().getValue()).isEqualTo(clientId);
      assertThat(event.getPlainTextSecret()).isNotBlank();
    }

    @Test
    void shouldGenerateClientSecret() {
      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.get().getClientSecret()).isNotNull();
    }

    @Test
    void shouldEncodeClientSecret() {
      createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      verify(passwordEncoder).encode(anyString());
    }
  }

  @Nested
  class ClientIdValidation {

    @Test
    void shouldFailWhenClientIdIsNull() {
      var result = createOidcClient.create(
          null, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientIdIsEmpty() {
      var result = createOidcClient.create(
          "", clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientIdIsBlank() {
      var result = createOidcClient.create(
          "   ", clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }
  }

  @Nested
  class ClientAlreadyExists {

    @Test
    void shouldFailWhenClientIdAlreadyExists() {
      var existingClient = mock(OidcClient.class);
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.of(existingClient));

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldReturnClientAlreadyExistsError() {
      var existingClient = mock(OidcClient.class);
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.of(existingClient));

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientAlreadyExists(clientId));
    }
  }

  @Nested
  class ClientNameValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenClientNameIsNull() {
      var result = createOidcClient.create(
          clientId, null, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientNameIsEmpty() {
      var result = createOidcClient.create(
          clientId, "", grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenClientNameIsBlank() {
      var result = createOidcClient.create(
          clientId, "   ", grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }
  }

  @Nested
  class GrantTypesValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenGrantTypesContainsInvalidValue() {
      var invalidGrantTypes = Set.of("invalid_grant_type");

      var result = createOidcClient.create(
          clientId, clientName, invalidGrantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenGrantTypesIsEmpty() {
      var result = createOidcClient.create(
          clientId, clientName, Set.of(), authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptValidGrantTypes() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var validGrantTypes = Set.of("authorization_code", "refresh_token", "client_credentials");

      var result = createOidcClient.create(
          clientId, clientName, validGrantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class AuthenticationMethodsValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenAuthMethodsContainsInvalidValue() {
      var invalidAuthMethods = Set.of("invalid_auth_method");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, invalidAuthMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptValidAuthenticationMethods() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var validAuthMethods = Set.of("client_secret_basic", "client_secret_post");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, validAuthMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class RedirectUrisValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenRedirectUriIsInvalid() {
      var invalidRedirectUris = Set.of("not-a-valid-uri");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          invalidRedirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenRedirectUriUsesHttpForNonLocalhost() {
      var httpRedirectUri = Set.of("http://example.com/callback");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          httpRedirectUri, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptHttpsRedirectUri() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var httpsRedirectUri = Set.of("https://example.com/callback");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          httpsRedirectUri, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptLocalhostHttpRedirectUri() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var localhostRedirectUri = Set.of("http://localhost:8080/callback");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          localhostRedirectUri, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptMultipleRedirectUris() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var multipleRedirectUris = Set.of(
          "https://example.com/callback",
          "https://example.com/callback2",
          "http://localhost:3000/callback");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          multipleRedirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getRedirectUris()).hasSize(3);
    }
  }

  @Nested
  class PostLogoutRedirectUrisValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenPostLogoutRedirectUriIsInvalid() {
      var invalidPostLogoutUris = Set.of("not-a-valid-uri");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, invalidPostLogoutUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptValidPostLogoutRedirectUris() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var validPostLogoutUris = Set.of("https://example.com/logout");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, validPostLogoutUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class ScopesValidation {

    @BeforeEach
    void setUp() {
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.empty());
    }

    @Test
    void shouldFailWhenScopeIsInvalid() {
      var invalidScopes = Set.of("invalid scope with spaces");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, invalidScopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldAcceptStandardOidcScopes() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var standardScopes = Set.of("openid", "profile", "email", "address", "phone");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, standardScopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldAcceptCustomScopes() {
      when(passwordEncoder.encode(anyString())).thenReturn("hashed-secret");
      when(clients.trigger(any(OAuthClientCreatedEvent.class)))
          .thenAnswer(invocation -> ((OAuthClientCreatedEvent) invocation.getArgument(0)).getClient());

      var customScopes = Set.of("openid", "custom:read", "custom:write");

      var result = createOidcClient.create(
          clientId, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, customScopes,
          tokenSettings, clientSettings);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  class ValidationOrder {

    @Test
    void shouldValidateClientIdBeforeCheckingExistence() {
      var result = createOidcClient.create(
          null, clientName, grantTypes, authenticationMethods,
          redirectUris, postLogoutRedirectUris, scopes,
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findByClientId(any());
    }

    @Test
    void shouldCheckExistenceBeforeValidatingOtherFields() {
      var existingClient = mock(OidcClient.class);
      when(clients.findByClientId(any(ClientId.class))).thenReturn(Optional.of(existingClient));

      var result = createOidcClient.create(
          clientId, null, Set.of("invalid"), Set.of("invalid"),
          Set.of("invalid"), Set.of("invalid"), Set.of("invalid scope"),
          tokenSettings, clientSettings);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientAlreadyExists(clientId));
    }
  }
}