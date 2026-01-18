package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientSecretRegeneratedEvent;
import com.hjusic.auth.domain.oidc.model.valueObjects.ClientSecret;
import com.hjusic.auth.domain.oidc.model.valueObjects.OAuthClientId;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RegenerateOidcClientSecretTest {

  @Mock
  private OidcClients clients;

  @Mock
  private PasswordEncoder passwordEncoder;

  @InjectMocks
  private RegenerateOidcClientSecret regenerateOidcClientSecret;

  private String validId;
  private OidcClient existingClient;
  private OAuthClientSecretRegeneratedEvent regeneratedEvent;
  private ClientSecret newClientSecret;
  private String plainTextSecret;

  @BeforeEach
  void setUp() {
    validId = "550e8400-e29b-41d4-a716-446655440000";
    existingClient = mock(OidcClient.class);
    plainTextSecret = "generated-plain-text-secret";
    regeneratedEvent = mock(OAuthClientSecretRegeneratedEvent.class);
    newClientSecret = mock(ClientSecret.class);
  }

  @Nested
  class SuccessfulRegeneration {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
      when(existingClient.regenerateSecret(passwordEncoder)).thenReturn(regeneratedEvent);
      when(regeneratedEvent.getNewClientSecret()).thenReturn(newClientSecret);
      when(newClientSecret.getPlainText()).thenReturn(plainTextSecret);
      when(clients.trigger(any(OAuthClientSecretRegeneratedEvent.class))).thenReturn(existingClient);
    }

    @Test
    void shouldRegenerateSecretSuccessfully() {
      var result = regenerateOidcClientSecret.regenerate(validId);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    void shouldLookUpClientById() {
      regenerateOidcClientSecret.regenerate(validId);

      var idCaptor = ArgumentCaptor.forClass(OAuthClientId.class);
      verify(clients).findById(idCaptor.capture());
      assertThat(idCaptor.getValue().getValue().toString()).isEqualTo(validId);
    }

    @Test
    void shouldCallRegenerateSecretOnClientWithPasswordEncoder() {
      regenerateOidcClientSecret.regenerate(validId);

      verify(existingClient).regenerateSecret(passwordEncoder);
    }

    @Test
    void shouldTriggerSecretRegeneratedEvent() {
      regenerateOidcClientSecret.regenerate(validId);

      verify(clients).trigger(regeneratedEvent);
    }

    @Test
    void shouldReturnUpdatedClient() {
      var result = regenerateOidcClientSecret.regenerate(validId);

      assertThat(result.get().client()).isEqualTo(existingClient);
    }

    @Test
    void shouldReturnPlainTextSecret() {
      var result = regenerateOidcClientSecret.regenerate(validId);

      assertThat(result.get().plainTextSecret()).isEqualTo(plainTextSecret);
    }

    @Test
    void shouldReturnResultWithBothClientAndSecret() {
      var result = regenerateOidcClientSecret.regenerate(validId);

      var regenerateResult = result.get();
      assertThat(regenerateResult.client()).isNotNull();
      assertThat(regenerateResult.plainTextSecret()).isNotNull();
      assertThat(regenerateResult.plainTextSecret()).isNotBlank();
    }
  }

  @Nested
  class IdValidation {

    @Test
    void shouldFailWhenIdIsNull() {
      var result = regenerateOidcClientSecret.regenerate(null);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsEmpty() {
      var result = regenerateOidcClientSecret.regenerate("");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsBlank() {
      var result = regenerateOidcClientSecret.regenerate("   ");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsInvalidFormat() {
      var result = regenerateOidcClientSecret.regenerate("not-a-valid-uuid");

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
      var result = regenerateOidcClientSecret.regenerate(validId);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    void shouldReturnClientNotFoundError() {
      var result = regenerateOidcClientSecret.regenerate(validId);

      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientNotFound(validId));
    }

    @Test
    void shouldNotTriggerEventWhenClientNotFound() {
      regenerateOidcClientSecret.regenerate(validId);

      verify(clients, never()).trigger(any(OAuthClientSecretRegeneratedEvent.class));
    }

    @Test
    void shouldNotCallRegenerateSecretWhenClientNotFound() {
      regenerateOidcClientSecret.regenerate(validId);

      verify(existingClient, never()).regenerateSecret(any(PasswordEncoder.class));
    }
  }

  @Nested
  class ValidationOrder {

    @Test
    void shouldValidateIdBeforeLookingUpClient() {
      var result = regenerateOidcClientSecret.regenerate("invalid-uuid");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
    }

    @Test
    void shouldLookUpClientBeforeRegeneratingSecret() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.empty());

      regenerateOidcClientSecret.regenerate(validId);

      verify(clients).findById(any(OAuthClientId.class));
      verify(existingClient, never()).regenerateSecret(any(PasswordEncoder.class));
    }
  }

  @Nested
  class RegenerateSecretResult {

    @Test
    void shouldCreateResultWithClientAndSecret() {
      var client = mock(OidcClient.class);
      var secret = "test-secret";

      var result = new RegenerateOidcClientSecret.RegenerateSecretResult(client, secret);

      assertThat(result.client()).isEqualTo(client);
      assertThat(result.plainTextSecret()).isEqualTo(secret);
    }

    @Test
    void shouldSupportRecordEquality() {
      var client = mock(OidcClient.class);
      var secret = "test-secret";

      var result1 = new RegenerateOidcClientSecret.RegenerateSecretResult(client, secret);
      var result2 = new RegenerateOidcClientSecret.RegenerateSecretResult(client, secret);

      assertThat(result1).isEqualTo(result2);
    }

    @Test
    void shouldNotBeEqualWithDifferentSecrets() {
      var client = mock(OidcClient.class);

      var result1 = new RegenerateOidcClientSecret.RegenerateSecretResult(client, "secret1");
      var result2 = new RegenerateOidcClientSecret.RegenerateSecretResult(client, "secret2");

      assertThat(result1).isNotEqualTo(result2);
    }
  }
}