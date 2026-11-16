package com.hjusic.auth.domain.mfa.model;

import java.time.Instant;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class MfaError {

  String message;
  MfaErrorCode code;

  public static MfaError unauthenticated() {
    return new MfaError("Not authenticated", MfaErrorCode.UNAUTHENTICATED);
  }

  public static MfaError validationFailed(String message) {
    return new MfaError(message, MfaErrorCode.VALIDATION_FAILED);
  }

  public static MfaError notEnrolled(String username) {
    return new MfaError("User '" + username + "' has no TOTP enrolled", MfaErrorCode.NOT_ENROLLED);
  }

  public static MfaError alreadyEnrolled() {
    return new MfaError("TOTP is already enabled; disable it first", MfaErrorCode.ALREADY_ENROLLED);
  }

  public static MfaError invalidCode() {
    return new MfaError("Invalid verification code", MfaErrorCode.INVALID_CODE);
  }

  public static MfaError locked(Instant lockedUntil) {
    return new MfaError("Too many invalid codes; locked until " + lockedUntil, MfaErrorCode.LOCKED);
  }
}
