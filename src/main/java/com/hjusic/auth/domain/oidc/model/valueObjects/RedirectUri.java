package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.Set;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class RedirectUri {
  String value;

  public static Either<OAuthClientError, RedirectUri> of(String uri) {
    if (uri == null || uri.isBlank()) {
      return Either.left(OAuthClientError.validationFailed("Redirect URI cannot be empty"));
    }
    try {
      URI parsed = new URI(uri);
      if (parsed.getScheme() == null) {
        return Either.left(OAuthClientError.validationFailed("Redirect URI must have a scheme: " + uri));
      }
    } catch (URISyntaxException e) {
      return Either.left(OAuthClientError.validationFailed("Invalid redirect URI: " + uri));
    }
    return Either.right(new RedirectUri(uri));
  }

  public static Either<OAuthClientError, Set<RedirectUri>> ofSet(Set<String> uris) {
    if (uris == null) {
      return Either.right(new HashSet<>());
    }
    Set<RedirectUri> result = new HashSet<>();
    for (String uri : uris) {
      var redirectUri = of(uri);
      if (redirectUri.isLeft()) {
        return Either.left(redirectUri.getLeft());
      }
      result.add(redirectUri.get());
    }
    return Either.right(result);
  }
}
