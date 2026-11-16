package com.hjusic.auth.domain.mfa.application;

/**
 * What the user needs to add the account to an authenticator app: the Base32 secret for manual
 * entry and the {@code otpauth://} URI to render as a QR code.
 */
public record TotpEnrollmentDetails(String secret, String otpAuthUri) {

  @Override
  public String toString() {
    return "TotpEnrollmentDetails[secret=****]";
  }
}
