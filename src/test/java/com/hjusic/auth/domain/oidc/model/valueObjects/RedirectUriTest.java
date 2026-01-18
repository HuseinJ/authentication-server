package com.hjusic.auth.domain.client.model.valueobject;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import com.hjusic.auth.domain.oidc.model.valueObjects.RedirectUri;
import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Set;

class RedirectUriTest {

  @Nested
  @DisplayName("Valid redirect URI creation")
  class ValidRedirectUriTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "http://localhost:8080/callback",
        "https://example.com/oauth/callback",
        "https://app.example.com/login/oauth2/code/provider",
        "http://127.0.0.1:3000/auth",
        "https://example.com:443/callback",
    })
    @DisplayName("Should accept valid redirect URI formats")
    void shouldAcceptValidFormats(String uri) {
      Either<OAuthClientError, RedirectUri> result = RedirectUri.of(uri);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo(uri);
    }

    @Test
    @DisplayName("Should create redirect URI with HTTPS")
    void shouldCreateHttpsRedirectUri() {
      Either<OAuthClientError, RedirectUri> result = RedirectUri.of("https://secure.example.com/callback");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).startsWith("https://");
    }
  }

  @Nested
  @DisplayName("Invalid redirect URI")
  class InvalidRedirectUriTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank redirect URI")
    void shouldRejectNullOrBlankRedirectUri(String uri) {
      Either<OAuthClientError, RedirectUri> result = RedirectUri.of(uri);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Redirect URI cannot be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "not-a-uri",
        "example.com/callback",        // Missing scheme
        "/just/a/path",                // No scheme
        "://missing-scheme.com"
    })
    @DisplayName("Should reject invalid redirect URI formats")
    void shouldRejectInvalidFormats(String uri) {
      Either<OAuthClientError, RedirectUri> result = RedirectUri.of(uri);

      assertThat(result.isLeft()).isTrue();
    }
  }

  @Nested
  @DisplayName("Redirect URI set creation")
  class RedirectUriSetTests {

    @Test
    @DisplayName("Should create set of valid redirect URIs")
    void shouldCreateValidSet() {
      Set<String> uris = Set.of(
          "http://localhost:8080/callback",
          "https://example.com/callback"
      );

      Either<com.hjusic.auth.domain.oidc.model.OAuthClientError, Set<RedirectUri>> result = RedirectUri.ofSet(uris);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).hasSize(2);
    }

    @Test
    @DisplayName("Should return empty set for null input")
    void shouldReturnEmptySetForNull() {
      Either<OAuthClientError, Set<RedirectUri>> result = RedirectUri.ofSet(null);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).isEmpty();
    }

    @Test
    @DisplayName("Should fail if any URI in set is invalid")
    void shouldFailIfAnyUriIsInvalid() {
      Set<String> uris = Set.of(
          "http://localhost:8080/callback",
          "invalid-uri"
      );

      Either<OAuthClientError, Set<RedirectUri>> result = RedirectUri.ofSet(uris);

      assertThat(result.isLeft()).isTrue();
    }
  }
}