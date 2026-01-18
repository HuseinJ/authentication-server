package com.hjusic.auth.domain.oidc.application;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.OidcClient;
import com.hjusic.auth.domain.oidc.model.OidcClients;
import com.hjusic.auth.domain.oidc.model.events.OAuthClientDeletedEvent;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeleteOidcClientTest {

  @Mock
  private OidcClients clients;

  @InjectMocks
  private DeleteOidcClient deleteOidcClient;

  private String validId;
  private OAuthClientId oauthClientId;
  private OidcClient existingClient;

  @BeforeEach
  void setUp() {
    validId = "550e8400-e29b-41d4-a716-446655440000";
    oauthClientId = OAuthClientId.of(validId).get();
    existingClient = mock(OidcClient.class);
  }

  @Nested
  class SuccessfulDeletion {

    @BeforeEach
    void setUp() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.of(existingClient));
      when(existingClient.delete()).thenReturn(OAuthClientDeletedEvent.of(existingClient));
      when(clients.trigger(any(OAuthClientDeletedEvent.class))).thenReturn(existingClient);
    }

    @Test
    void shouldDeleteClientSuccessfully() {
      var result = deleteOidcClient.delete(validId);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(existingClient);
    }

    @Test
    void shouldLookUpClientById() {
      deleteOidcClient.delete(validId);

      var idCaptor = ArgumentCaptor.forClass(OAuthClientId.class);
      verify(clients).findById(idCaptor.capture());
      assertThat(idCaptor.getValue().getValue().toString()).isEqualTo(validId);
    }

    @Test
    void shouldCallDeleteOnClient() {
      deleteOidcClient.delete(validId);

      verify(existingClient).delete();
    }

    @Test
    void shouldTriggerDeletedEvent() {
      deleteOidcClient.delete(validId);

      var eventCaptor = ArgumentCaptor.forClass(OAuthClientDeletedEvent.class);
      verify(clients).trigger(eventCaptor.capture());
      assertThat(eventCaptor.getValue().getClient()).isEqualTo(existingClient);
    }

    @Test
    void shouldReturnDeletedClient() {
      var result = deleteOidcClient.delete(validId);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(existingClient);
    }
  }

  @Nested
  class IdValidation {

    @Test
    void shouldFailWhenIdIsNull() {
      var result = deleteOidcClient.delete(null);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsEmpty() {
      var result = deleteOidcClient.delete("");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsBlank() {
      var result = deleteOidcClient.delete("   ");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldFailWhenIdIsInvalidFormat() {
      var result = deleteOidcClient.delete("not-a-valid-uuid");

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
      var result = deleteOidcClient.delete(validId);

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).trigger(any());
    }

    @Test
    void shouldReturnClientNotFoundError() {
      var result = deleteOidcClient.delete(validId);

      assertThat(result.getLeft()).isEqualTo(OAuthClientError.clientNotFound(validId));
    }

    @Test
    void shouldNotTriggerEventWhenClientNotFound() {
      deleteOidcClient.delete(validId);

      verify(clients, never()).trigger(any(OAuthClientDeletedEvent.class));
    }
  }

  @Nested
  class ValidationOrder {

    @Test
    void shouldValidateIdBeforeLookingUpClient() {
      var result = deleteOidcClient.delete("invalid-uuid");

      assertThat(result.isLeft()).isTrue();
      verify(clients, never()).findById(any());
    }

    @Test
    void shouldLookUpClientBeforeDeleting() {
      when(clients.findById(any(OAuthClientId.class))).thenReturn(Optional.empty());

      deleteOidcClient.delete(validId);

      verify(clients).findById(any(OAuthClientId.class));
      verify(clients, never()).trigger(any());
    }
  }
}