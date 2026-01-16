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

import java.util.Set;

class ScopeTest {

  @Nested
  @DisplayName("Valid scope creation")
  class ValidScopeTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "openid",
        "profile",
        "email",
        "address",
        "phone",
        "read",
        "write",
        "read:users",
        "api:read",
        "custom_scope",
        "scope-with-dash",
        "scope/with/slash",
        "scope.with.dots"
    })
    @DisplayName("Should accept valid scope formats")
    void shouldAcceptValidFormats(String scope) {
      Either<OAuthClientError, Scope> result = Scope.of(scope);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo(scope);
    }

    @Test
    @DisplayName("Should create standard OIDC openid scope")
    void shouldCreateOpenidScope() {
      Either<OAuthClientError, Scope> result = Scope.of(Scope.OPENID);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("openid");
    }
  }

  @Nested
  @DisplayName("Invalid scope")
  class InvalidScopeTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank scope")
    void shouldRejectNullOrBlankScope(String scope) {
      Either<OAuthClientError, Scope> result = Scope.of(scope);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Scope cannot be empty");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "scope with spaces",
        "scope@invalid",
        "scope#invalid",
        "scope!invalid"
    })
    @DisplayName("Should reject invalid scope formats")
    void shouldRejectInvalidFormats(String scope) {
      Either<OAuthClientError, Scope> result = Scope.of(scope);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid scope format");
    }
  }

  @Nested
  @DisplayName("Scope set creation")
  class ScopeSetTests {

    @Test
    @DisplayName("Should create set of valid scopes")
    void shouldCreateValidSet() {
      Set<String> scopes = Set.of("openid", "profile", "email");

      Either<OAuthClientError, Set<Scope>> result = Scope.ofSet(scopes);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get()).hasSize(3);
    }

    @Test
    @DisplayName("Should reject empty scope set")
    void shouldRejectEmptySet() {
      Either<OAuthClientError, Set<Scope>> result = Scope.ofSet(Set.of());

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("At least one scope is required");
    }

    @Test
    @DisplayName("Should reject null scope set")
    void shouldRejectNullSet() {
      Either<OAuthClientError, Set<Scope>> result = Scope.ofSet(null);

      assertThat(result.isLeft()).isTrue();
    }

    @Test
    @DisplayName("Should fail if any scope in set is invalid")
    void shouldFailIfAnyScopeIsInvalid() {
      Set<String> scopes = Set.of("openid", "invalid scope");

      Either<OAuthClientError, Set<Scope>> result = Scope.ofSet(scopes);

      assertThat(result.isLeft()).isTrue();
    }
  }
}