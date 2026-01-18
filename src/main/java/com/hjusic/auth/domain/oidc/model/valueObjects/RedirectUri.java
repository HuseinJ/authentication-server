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

    URI parsed;
    try {
      parsed = new URI(uri);
      if (parsed.getScheme() == null) {
        return Either.left(OAuthClientError.validationFailed("Redirect URI must have a scheme: " + uri));
      }
    } catch (URISyntaxException e) {
      return Either.left(OAuthClientError.validationFailed("Invalid redirect URI: " + uri));
    }

    String scheme = parsed.getScheme().toLowerCase();
    if (!scheme.equals("http") && !scheme.equals("https")) {
      return Either.left(OAuthClientError.validationFailed("Redirect URI must use http or https scheme: " + uri));
    }

    if (scheme.equals("http") && !isLocalhost(parsed.getHost())) {
      return Either.left(OAuthClientError.validationFailed("Non-localhost redirect URI must use https: " + uri));
    }

    return Either.right(new RedirectUri(uri));
  }

  private static boolean isLocalhost(String host) {
    if (host == null) {
      return false;
    }
    return host.equalsIgnoreCase("localhost")
        || host.equals("127.0.0.1")
        || host.equals("::1");
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