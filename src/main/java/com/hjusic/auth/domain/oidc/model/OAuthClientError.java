package com.hjusic.auth.domain.oidc.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class OAuthClientError {
  String message;
  OAuthClientErrorCode code;

  public static OAuthClientError of(String message, OAuthClientErrorCode code) {
    return new OAuthClientError(message, code);
  }

  public static OAuthClientError clientNotFound(String clientId) {
    return new OAuthClientError("OAuth client not found: " + clientId, OAuthClientErrorCode.CLIENT_NOT_FOUND);
  }

  public static OAuthClientError clientAlreadyExists(String clientId) {
    return new OAuthClientError("OAuth client already exists: " + clientId, OAuthClientErrorCode.CLIENT_ALREADY_EXISTS);
  }

  public static OAuthClientError validationFailed(String message) {
    return new OAuthClientError(message, OAuthClientErrorCode.VALIDATION_FAILED);
  }

  public static OAuthClientError deletionFailed(String message) {
    return new OAuthClientError(message, OAuthClientErrorCode.DELETION_FAILED);
  }

  public static OAuthClientError unauthorized(String message) {
    return new OAuthClientError(message, OAuthClientErrorCode.UNAUTHORIZED);
  }
}

