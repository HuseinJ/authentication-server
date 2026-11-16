package com.hjusic.auth.domain.mfa.model.valueObjects;

import com.hjusic.auth.domain.mfa.model.MfaError;
import io.vavr.control.Either;
import java.util.regex.Pattern;

/** A code as typed by the user from their authenticator app. */
public final class TotpCode {

  private static final Pattern FORMAT = Pattern.compile("\\d{" + TotpAlgorithm.DIGITS + "}");

  private final String value;

  private TotpCode(String value) {
    this.value = value;
  }

  public static Either<MfaError, TotpCode> of(String raw) {
    if (raw == null) {
      return Either.left(MfaError.validationFailed("Code must not be empty"));
    }
    String normalized = raw.replace(" ", "").trim();
    if (!FORMAT.matcher(normalized).matches()) {
      return Either.left(
          MfaError.validationFailed("Code must be " + TotpAlgorithm.DIGITS + " digits"));
    }
    return Either.right(new TotpCode(normalized));
  }

  public String getValue() {
    return value;
  }

  @Override
  public String toString() {
    return "TotpCode[******]";
  }
}
