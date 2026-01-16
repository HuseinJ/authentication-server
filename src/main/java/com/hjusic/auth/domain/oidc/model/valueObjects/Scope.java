package com.hjusic.auth.domain.oidc.model.valueObjects;

import com.hjusic.auth.domain.oidc.model.OAuthClientError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Scope {
  private static final Pattern SCOPE_PATTERN = Pattern.compile("^[a-zA-Z0-9_:./-]+$");

  // Standard OIDC scopes
  public static final String OPENID = "openid";
  public static final String PROFILE = "profile";
  public static final String EMAIL = "email";
  public static final String ADDRESS = "address";
  public static final String PHONE = "phone";

  String value;

  public static Either<OAuthClientError, Scope> of(String scope) {
    if (scope == null || scope.isBlank()) {
      return Either.left(OAuthClientError.validationFailed("Scope cannot be empty"));
    }
    if (!SCOPE_PATTERN.matcher(scope).matches()) {
      return Either.left(OAuthClientError.validationFailed("Invalid scope format: " + scope));
    }
    return Either.right(new Scope(scope));
  }

  public static Either<OAuthClientError, Set<Scope>> ofSet(Set<String> scopes) {
    if (scopes == null || scopes.isEmpty()) {
      return Either.left(OAuthClientError.validationFailed("At least one scope is required"));
    }
    Set<Scope> result = new HashSet<>();
    for (String scope : scopes) {
      var validatedScope = of(scope);
      if (validatedScope.isLeft()) {
        return Either.left(validatedScope.getLeft());
      }
      result.add(validatedScope.get());
    }
    return Either.right(result);
  }
}

