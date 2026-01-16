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

class ClientNameTest {

  @Nested
  @DisplayName("Valid client name creation")
  class ValidClientNameTests {

    @Test
    @DisplayName("Should create client name with valid value")
    void shouldCreateValidClientName() {
      Either<OAuthClientError, ClientName> result = ClientName.of("My Application");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("My Application");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "App",
        "My Web Application",
        "OAuth Client #1",
        "Test Client (Development)",
        "Production API - v2.0"
    })
    @DisplayName("Should accept valid client name formats")
    void shouldAcceptValidFormats(String name) {
      Either<OAuthClientError, ClientName> result = ClientName.of(name);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept client name with exactly 200 characters")
    void shouldAcceptMaxLengthClientName() {
      String name = "a".repeat(200);
      Either<OAuthClientError, ClientName> result = ClientName.of(name);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).hasSize(200);
    }
  }

  @Nested
  @DisplayName("Invalid client name")
  class InvalidClientNameTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank client name")
    void shouldRejectNullOrBlankClientName(String name) {
      Either<OAuthClientError, ClientName> result = ClientName.of(name);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Client name cannot be empty");
    }

    @Test
    @DisplayName("Should reject client name exceeding 200 characters")
    void shouldRejectClientNameExceedingMaxLength() {
      String name = "a".repeat(201);

      Either<OAuthClientError, ClientName> result = ClientName.of(name);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("cannot exceed 200 characters");
    }
  }
}