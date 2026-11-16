package com.hjusic.auth.domain.mfa.model;

import java.util.Arrays;
import java.util.Optional;

/**
 * The second factors a user can enroll in addition to their password.
 *
 * <p>This is the extension point for new MFA methods: adding e.g. {@code WEBAUTHN("webauthn",
 * "WEBAUTHN")} (passkeys / YubiKeys), together with a {@link SecondFactorEnrollment} for it, makes
 * the login flows require it for every user who has it enrolled.
 *
 * @param id     stable, lower-case identifier used in URLs and API payloads
 * @param factor factor name; Spring Security grants it as the {@code FACTOR_<factor>} authority
 *               once the factor has been verified (e.g. {@code FACTOR_TOTP}). For WebAuthn this
 *               must be {@code WEBAUTHN} so it matches Spring's built-in {@code FACTOR_WEBAUTHN}.
 */
public enum SecondFactorType {

  TOTP("totp", "TOTP");

  private final String id;
  private final String factor;

  SecondFactorType(String id, String factor) {
    this.id = id;
    this.factor = factor;
  }

  public String getId() {
    return id;
  }

  public String getFactor() {
    return factor;
  }

  public static Optional<SecondFactorType> fromFactor(String factor) {
    return Arrays.stream(values()).filter(type -> type.factor.equals(factor)).findFirst();
  }
}
