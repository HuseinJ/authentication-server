package com.hjusic.auth.domain.user.model.ValueObjects;

import com.hjusic.auth.domain.user.model.UserError;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.StringUtils;

import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

@Getter
@EqualsAndHashCode
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public final class Password {

  // OWASP recommends minimum 8 characters, no maximum (or very high like 128)
  private static final int MIN_LENGTH = 8;
  private static final int MAX_LENGTH = 128;

  private final String value;

  public static Either<UserError, Password> encode(String password, PasswordEncoder encoder) {
    return validateNotEmpty(password)
        .flatMap(Password::validateLength)
        .map(either -> new Password(encoder.encode(either)));
  }

  private static Either<UserError, String> validateNotEmpty(String password) {
    return StringUtils.hasText(password)
        ? Either.right(password)
        : Either.left(UserError.validationFailed("Password cannot be empty"));
  }

  private static Either<UserError, String> validateLength(String password) {
    if (password.length() < MIN_LENGTH) {
      return Either.left(UserError.validationFailed(
          "Password must be at least " + MIN_LENGTH + " characters"
      ));
    }
    if (password.length() > MAX_LENGTH) {
      return Either.left(UserError.validationFailed(
          "Password cannot exceed " + MAX_LENGTH + " characters"
      ));
    }
    return Either.right(password);
  }

  // Prevent serialization
  private void writeObject(ObjectOutputStream out) throws NotSerializableException {
    throw new NotSerializableException("Password objects cannot be serialized for security reasons");
  }

  private void readObject(ObjectInputStream in) throws NotSerializableException {
    throw new NotSerializableException("Password objects cannot be deserialized for security reasons");
  }

  // Override toString to prevent accidental password exposure in logs
  @Override
  public String toString() {
    return "Password[PROTECTED]";
  }
}