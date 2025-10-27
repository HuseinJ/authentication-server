package com.hjusic.auth.domain.user.model;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class UserError {

  String message;
  UserErrorCode code;

  public static UserError of(String message, UserErrorCode code) {
    return new UserError(message, code);
  }

  public static UserError userNotFound(String username) {
    return new UserError("User '" + username + "' not found", UserErrorCode.USER_NOT_FOUND);
  }

  public static UserError validationFailed(String message) {
    return new UserError(message, UserErrorCode.VALIDATION_FAILED);
  }

  public static UserError creationFailed(String message) {
    return new UserError(message, UserErrorCode.USER_CREATION_FAILED);
  }

  public static UserError deletionFailed(String message) {
    return new UserError(message, UserErrorCode.USER_CREATION_FAILED);
  }

  public static UserError invalidResetPasswordToken(String message) {
    return new UserError(message, UserErrorCode.RESET_PASSWORD_TOKEN_VALIDATION_FAILED);
  }

  public static UserError unauthenticated(String message) {
    return new UserError(message, UserErrorCode.UNAUTHENTICATED);
  }

}