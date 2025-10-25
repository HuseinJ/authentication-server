package com.hjusic.auth.domain.user.model.ValueObjects;

import com.hjusic.auth.domain.user.model.UserError;
import io.micrometer.common.util.StringUtils;
import io.vavr.control.Either;
import java.util.regex.Pattern;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class Email {

  private static final int MAX_LENGTH = 255;

  private static final Pattern EMAIL_PATTERN = Pattern.compile(
      "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$"
  );

  String value;

  public static Either<UserError, Email> of(String email) {

    if (StringUtils.isBlank(email)) {
      return Either.left(UserError.validationFailed(
          "Email cannot be empty"
      ));
    }

    String trimmedEmail = email.trim();

    if (!EMAIL_PATTERN.matcher(trimmedEmail).matches()) {
      return Either.left(UserError.validationFailed(
          "Invalid email format"
      ));
    }

    if (trimmedEmail.length() > MAX_LENGTH) {
      return Either.left(UserError.validationFailed(
          "Email cannot exceed "+ MAX_LENGTH +" characters"
      ));
    }

    return Either.right(new Email(trimmedEmail.toLowerCase()));
  }
}
