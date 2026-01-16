package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.util.regex.Pattern;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class ClientId {
  private static final Pattern CLIENT_ID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]{3,100}$");

  String value;

  public static Either<OAuthClientError, ClientId> of(String clientId) {
    if (clientId == null || clientId.isBlank()) {
      return Either.left(OAuthClientError.validationFailed("Client ID cannot be empty"));
    }
    if (!CLIENT_ID_PATTERN.matcher(clientId).matches()) {
      return Either.left(OAuthClientError.validationFailed(
          "Client ID must be 3-100 characters and contain only alphanumeric characters, hyphens, or underscores"));
    }
    return Either.right(new ClientId(clientId));
  }
}

