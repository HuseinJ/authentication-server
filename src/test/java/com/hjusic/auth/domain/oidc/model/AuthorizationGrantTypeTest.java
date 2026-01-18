package com.hjusic.auth.domain.oidc.model;

import static org.assertj.core.api.Assertions.assertThat;

import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

class AuthorizationGrantTypeTest {

  @Nested
  @DisplayName("Valid grant type creation")
  class ValidGrantTypeTests {

    @Test
    @DisplayName("Should create authorization_code grant type")
    void shouldCreateAuthorizationCodeGrantType() {
      Either<OAuthClientError, AuthorizationGrantType> result =
          AuthorizationGrantType.of("authorization_code");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(AuthorizationGrantType.AUTHORIZATION_CODE);
    }

    @Test
    @DisplayName("Should create client_credentials grant type")
    void shouldCreateClientCredentialsGrantType() {
      Either<OAuthClientError, AuthorizationGrantType> result =
          AuthorizationGrantType.of("client_credentials");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(AuthorizationGrantType.CLIENT_CREDENTIALS);
    }

    @Test
    @DisplayName("Should create refresh_token grant type")
    void shouldCreateRefreshTokenGrantType() {
      Either<OAuthClientError, AuthorizationGrantType> result =
          AuthorizationGrantType.of("refresh_token");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(AuthorizationGrantType.REFRESH_TOKEN);
    }

    @Test
    @DisplayName("Should create device_code grant type")
    void shouldCreateDeviceCodeGrantType() {
      Either<OAuthClientError, AuthorizationGrantType> result =
          AuthorizationGrantType.of("urn:ietf:params:oauth:grant-type:device_code");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEqualTo(AuthorizationGrantType.DEVICE_CODE);
    }
  }

  @Nested
  @DisplayName("Invalid grant type")
  class InvalidGrantTypeTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid",
        "password",                    // Not supported
        "implicit",                    // Deprecated
        "authorization-code",          // Wrong format
        "AUTHORIZATION_CODE"           // Wrong case
    })
    @DisplayName("Should reject invalid grant types")
    void shouldRejectInvalidGrantTypes(String grantType) {
      Either<OAuthClientError, AuthorizationGrantType> result =
          AuthorizationGrantType.of(grantType);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid grant type");
    }
  }

  @Nested
  @DisplayName("Grant type set creation")
  class GrantTypeSetTests {

    @Test
    @DisplayName("Should create set of valid grant types")
    void shouldCreateValidSet() {
      Set<String> grantTypes = Set.of("authorization_code", "refresh_token");

      Either<OAuthClientError, Set<AuthorizationGrantType>> result =
          AuthorizationGrantType.ofSet(grantTypes);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).hasSize(2);
      assertThat(result.get()).contains(
          AuthorizationGrantType.AUTHORIZATION_CODE,
          AuthorizationGrantType.REFRESH_TOKEN
      );
    }

    @Test
    @DisplayName("Should reject empty grant type set")
    void shouldRejectEmptySet() {
      Either<OAuthClientError, Set<AuthorizationGrantType>> result =
          AuthorizationGrantType.ofSet(Set.of());

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("At least one grant type is required");
    }

    @Test
    @DisplayName("Should reject null grant type set")
    void shouldRejectNullSet() {
      Either<OAuthClientError, Set<AuthorizationGrantType>> result =
          AuthorizationGrantType.ofSet(null);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    @DisplayName("Should fail if any grant type in set is invalid")
    void shouldFailIfAnyGrantTypeIsInvalid() {
      Set<String> grantTypes = Set.of("authorization_code", "invalid_type");

      Either<OAuthClientError, Set<AuthorizationGrantType>> result =
          AuthorizationGrantType.ofSet(grantTypes);

      assertThat(result.isLeft()).isTrue();
    }
  }
}