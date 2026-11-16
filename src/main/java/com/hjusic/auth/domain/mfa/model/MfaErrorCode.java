package com.hjusic.auth.domain.mfa.model;

public enum MfaErrorCode {
  UNAUTHENTICATED,
  VALIDATION_FAILED,
  NOT_ENROLLED,
  ALREADY_ENROLLED,
  INVALID_CODE,
  LOCKED
}
