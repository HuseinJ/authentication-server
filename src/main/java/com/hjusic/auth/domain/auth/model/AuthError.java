package com.hjusic.auth.domain.auth.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthError {

  String message;
  AuthErrorCode code;

  public static AuthError of(String message, AuthErrorCode code) {
    return new AuthError(message, code);
  }

  public static AuthError notAuthenticated() {
    return new AuthError("No user in session", AuthErrorCode.AUTHENTICATION_NOT_FOUND);
  }

  public static AuthError notAuthenticated(String message) {
    return new AuthError(message, AuthErrorCode.AUTHENTICATION_NOT_FOUND);
  }

}
