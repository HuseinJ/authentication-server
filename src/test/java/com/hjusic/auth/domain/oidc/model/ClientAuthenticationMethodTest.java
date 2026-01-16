package com.hjusic.auth.domain.oidc.model;

import static org.assertj.core.api.Assertions.assertThat;

import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

class ClientAuthenticationMethodTest {

  @Nested
  @DisplayName("Valid authentication method creation")
  class ValidAuthMethodTests {

    @Test
    @DisplayName("Should create client_secret_basic method")
    void shouldCreateClientSecretBasicMethod() {
      Either<OAuthClientError, ClientAuthenticationMethod> result =
          ClientAuthenticationMethod.of("client_secret_basic");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
    }

    @Test
    @DisplayName("Should create client_secret_post method")
    void shouldCreateClientSecretPostMethod() {
      Either<OAuthClientError, ClientAuthenticationMethod> result =
          ClientAuthenticationMethod.of("client_secret_post");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(ClientAuthenticationMethod.CLIENT_SECRET_POST);
    }

    @Test
    @DisplayName("Should create none method for public clients")
    void shouldCreateNoneMethod() {
      Either<OAuthClientError, ClientAuthenticationMethod> result =
          ClientAuthenticationMethod.of("none");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(ClientAuthenticationMethod.NONE);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none"
    })
    @DisplayName("Should accept all valid authentication methods")
    void shouldAcceptAllValidMethods(String method) {
      Either<OAuthClientError, ClientAuthenticationMethod> result =
          ClientAuthenticationMethod.of(method);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  @DisplayName("Invalid authentication method")
  class InvalidAuthMethodTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid",
        "basic",
        "CLIENT_SECRET_BASIC",          // Wrong case
        "client-secret-basic"           // Wrong format
    })
    @DisplayName("Should reject invalid authentication methods")
    void shouldRejectInvalidMethods(String method) {
      Either<OAuthClientError, ClientAuthenticationMethod> result =
          ClientAuthenticationMethod.of(method);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid authentication method");
    }
  }

  @Nested
  @DisplayName("Authentication method set creation")
  class AuthMethodSetTests {

    @Test
    @DisplayName("Should create set of valid authentication methods")
    void shouldCreateValidSet() {
      Set<String> methods = Set.of("client_secret_basic", "client_secret_post");

      Either<OAuthClientError, Set<ClientAuthenticationMethod>> result =
          ClientAuthenticationMethod.ofSet(methods);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).hasSize(2);
    }

    @Test
    @DisplayName("Should reject empty authentication method set")
    void shouldRejectEmptySet() {
      Either<OAuthClientError, Set<ClientAuthenticationMethod>> result =
          ClientAuthenticationMethod.ofSet(Set.of());

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("At least one authentication method is required");
    }

    @Test
    @DisplayName("Should reject null authentication method set")
    void shouldRejectNullSet() {
      Either<OAuthClientError, Set<ClientAuthenticationMethod>> result =
          ClientAuthenticationMethod.ofSet(null);

      assertThat(result.isLeft()).isTrue();
    }
  }
}