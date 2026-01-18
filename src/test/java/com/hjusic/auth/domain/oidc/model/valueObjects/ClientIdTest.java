package com.hjusic.auth.domain.oidc.model.valueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class ClientIdTest {

  @Nested
  @DisplayName("Valid client ID creation")
  class ValidClientIdTests {

    @Test
    @DisplayName("Should create client ID with valid format")
    void shouldCreateValidClientId() {
      Either<OAuthClientError, ClientId> result = ClientId.of("my-client-app");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("my-client-app");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "client",
        "my-client",
        "my_client",
        "myClient123",
        "CLIENT-APP-001",
        "abc",
        "a-b-c",
        "client_with_underscores",
        "MixedCase-Client_123"
    })
    @DisplayName("Should accept valid client ID formats")
    void shouldAcceptValidFormats(String clientId) {
      Either<OAuthClientError, ClientId> result = ClientId.of(clientId);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo(clientId);
    }

    @Test
    @DisplayName("Should accept client ID with exactly 3 characters")
    void shouldAcceptMinLengthClientId() {
      Either<OAuthClientError, ClientId> result = ClientId.of("abc");

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept client ID with exactly 100 characters")
    void shouldAcceptMaxLengthClientId() {
      String clientId = "a".repeat(100);
      Either<OAuthClientError, ClientId> result = ClientId.of(clientId);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).hasSize(100);
    }
  }

  @Nested
  @DisplayName("Invalid client ID - null or blank")
  class NullOrBlankTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank client ID")
    void shouldRejectNullOrBlankClientId(String clientId) {
      Either<OAuthClientError, ClientId> result = ClientId.of(clientId);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Client ID cannot be empty");
    }
  }

  @Nested
  @DisplayName("Invalid client ID - format")
  class InvalidFormatTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "ab",                           // too short
        "a",                            // too short
        "client with spaces",           // contains spaces
        "client@app",                   // contains @
        "client.app",                   // contains .
        "client!app",                   // contains !
        "client#app",                   // contains #
        "клиент"                        // non-ASCII characters
    })
    @DisplayName("Should reject invalid client ID formats")
    void shouldRejectInvalidFormats(String clientId) {
      Either<OAuthClientError, ClientId> result = ClientId.of(clientId);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    @DisplayName("Should reject client ID exceeding 100 characters")
    void shouldRejectClientIdExceedingMaxLength() {
      String clientId = "a".repeat(101);

      Either<OAuthClientError, ClientId> result = ClientId.of(clientId);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("3-100 characters");
    }
  }
}