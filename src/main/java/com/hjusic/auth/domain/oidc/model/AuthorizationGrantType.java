package com.hjusic.auth.domain.oidc.model;

import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.HashSet;
import java.util.Set;


@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Getter
public enum AuthorizationGrantType {
  AUTHORIZATION_CODE("authorization_code"),
  CLIENT_CREDENTIALS("client_credentials"),
  REFRESH_TOKEN("refresh_token"),
  DEVICE_CODE("urn:ietf:params:oauth:grant-type:device_code");

  private final String value;

  public static Either<OAuthClientError, AuthorizationGrantType> of(String value) {
    for (AuthorizationGrantType type : values()) {
      if (type.value.equals(value)) {
        return Either.right(type);
      }
    }
    return Either.left(OAuthClientError.validationFailed("Invalid grant type: " + value));
  }

  public static Either<OAuthClientError, Set<AuthorizationGrantType>> ofSet(Set<String> values) {
    if (values == null || values.isEmpty()) {
      return Either.left(OAuthClientError.validationFailed("At least one grant type is required"));
    }
    Set<AuthorizationGrantType> result = new HashSet<>();
    for (String value : values) {
      var grantType = of(value);
      if (grantType.isLeft()) {
        return Either.left(grantType.getLeft());
      }
      result.add(grantType.get());
    }
    return Either.right(result);
  }
}

