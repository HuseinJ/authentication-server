package com.hjusic.auth.domain.oidc.model;

import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashSet;
import java.util.Set;

@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum ClientAuthenticationMethod {
  CLIENT_SECRET_BASIC("client_secret_basic"),
  CLIENT_SECRET_POST("client_secret_post"),
  CLIENT_SECRET_JWT("client_secret_jwt"),
  PRIVATE_KEY_JWT("private_key_jwt"),
  NONE("none");

  private final String value;

  public static Either<OAuthClientError, ClientAuthenticationMethod> of(String value) {
    for (ClientAuthenticationMethod method : values()) {
      if (method.value.equals(value)) {
        return Either.right(method);
      }
    }
    return Either.left(OAuthClientError.validationFailed("Invalid authentication method: " + value));
  }

  public static Either<OAuthClientError, Set<ClientAuthenticationMethod>> ofSet(Set<String> values) {
    if (values == null || values.isEmpty()) {
      return Either.left(OAuthClientError.validationFailed("At least one authentication method is required"));
    }
    Set<ClientAuthenticationMethod> result = new HashSet<>();
    for (String value : values) {
      var method = of(value);
      if (method.isLeft()) {
        return Either.left(method.getLeft());
      }
      result.add(method.get());
    }
    return Either.right(result);
  }
}

