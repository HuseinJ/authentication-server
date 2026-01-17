package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.util.UUID;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuthClientId {
  UUID value;

  public static OAuthClientId generate() {
    return new OAuthClientId(UUID.randomUUID());
  }

  public static OAuthClientId of(UUID id) {
    return new OAuthClientId(id);
  }

  public static Either<OAuthClientError, OAuthClientId> of(String id) {

    if (id == null || id.isBlank()) {
      return Either.left(OAuthClientError.validationFailed("OAuth Client ID cannot be empty"));
    }

    try {
      return Either.right(new OAuthClientId(UUID.fromString(id)));
    } catch (IllegalArgumentException e) {
      return Either.left(OAuthClientError.validationFailed("Invalid OAuth Client ID format: " + id));
    }
  }
}

