package com.hjusic.auth.domain.user.model.ValueObjects;


import com.hjusic.auth.domain.user.model.UserError;
import io.vavr.control.Either;
import io.vavr.control.Validation;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;
import org.springframework.util.StringUtils;

import java.util.function.Predicate;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Username {

  String value;

  private static final int MIN_LENGTH = 3;
  private static final int MAX_LENGTH = 50;
  private static final String USERNAME_PATTERN = "^[a-zA-Z0-9_-]+$";

  public static Either<UserError, Username> of(String username) {
    return validateNotEmpty(username)
        .flatMap(Username::validateLength)
        .flatMap(Username::validatePattern)
        .map(Username::new);
  }

  private static Either<UserError, String> validateNotEmpty(String username) {
    return StringUtils.hasText(username)
        ? Either.right(username.trim())
        : Either.left(UserError.validationFailed("Username cannot be empty"));
  }

  private static Either<UserError, String> validateLength(String username) {
    if (username.length() < MIN_LENGTH) {
      return Either.left(UserError.validationFailed(
          "Username must be at least " + MIN_LENGTH + " characters"
      ));
    }
    if (username.length() > MAX_LENGTH) {
      return Either.left(UserError.validationFailed(
          "Username cannot exceed " + MAX_LENGTH + " characters"
      ));
    }
    return Either.right(username);
  }

  private static Either<UserError, String> validatePattern(String username) {
    return username.matches(USERNAME_PATTERN)
        ? Either.right(username)
        : Either.left(UserError.validationFailed(
            "Username can only contain letters, numbers, underscores, and hyphens"
        ));
  }

  @Override
  public String toString() {
    return value;
  }
}
