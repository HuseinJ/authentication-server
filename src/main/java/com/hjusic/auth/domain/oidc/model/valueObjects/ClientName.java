package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientName {
  String value;

  public static Either<OAuthClientError, ClientName> of(String name) {
    if (name == null || name.isBlank()) {
      return Either.left(OAuthClientError.validationFailed("Client name cannot be empty"));
    }
    if (name.length() > 200) {
      return Either.left(OAuthClientError.validationFailed("Client name cannot exceed 200 characters"));
    }
    return Either.right(new ClientName(name));
  }
}
