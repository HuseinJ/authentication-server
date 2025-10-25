package com.hjusic.auth.domain.user.model.ValueObjects;

import static org.assertj.core.api.Assertions.assertThat;

import com.hjusic.auth.domain.user.model.UserError;
import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class EmailTest {

  @Nested
  @DisplayName("Valid email creation")
  class ValidEmailTests {

    @Test
    @DisplayName("Should create email with valid format")
    void shouldCreateValidEmail() {
      Either<UserError, Email> result = Email.of("user@example.com");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("user@example.com");
    }

    @Test
    @DisplayName("Should convert email to lowercase")
    void shouldConvertToLowercase() {
      Either<UserError, Email> result = Email.of("User@Example.COM");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("user@example.com");
    }

    @Test
    @DisplayName("Should trim whitespace from email")
    void shouldTrimWhitespace() {
      Either<UserError, Email> result = Email.of("  user@example.com  ");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("user@example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "simple@example.com",
        "user.name@example.com",
        "user+tag@example.com",
        "user_name@example.com",
        "user-name@example.com",
        "123@example.com",
        "user@sub.example.com",
        "user@example.co.uk"
    })
    @DisplayName("Should accept valid email formats")
    void shouldAcceptValidFormats(String email) {
      Either<UserError, Email> result = Email.of(email);

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  @DisplayName("Invalid email - null or blank")
  class NullOrBlankTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank email")
    void shouldRejectNullOrBlankEmail(String email) {
      Either<UserError, Email> result = Email.of(email);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Email cannot be empty");
    }
  }

  @Nested
  @DisplayName("Invalid email - format")
  class InvalidFormatTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid",
        "invalid@",
        "@example.com",
        "invalid@.com",
        "invalid@domain",
        "invalid @example.com",
        "invalid@exam ple.com",
        "invalid@example.c"
    })
    @DisplayName("Should reject invalid email formats")
    void shouldRejectInvalidFormats(String email) {
      Either<UserError, Email> result = Email.of(email);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid email format");
    }

    @Test
    @DisplayName("Should reject email without @ symbol")
    void shouldRejectEmailWithoutAtSymbol() {
      Either<UserError, Email> result = Email.of("userexample.com");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid email format");
    }

    @Test
    @DisplayName("Should reject email without domain")
    void shouldRejectEmailWithoutDomain() {
      Either<UserError, Email> result = Email.of("user@");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid email format");
    }

    @Test
    @DisplayName("Should reject email with multiple @ symbols")
    void shouldRejectEmailWithMultipleAtSymbols() {
      Either<UserError, Email> result = Email.of("user@@example.com");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Invalid email format");
    }
  }

  @Nested
  @DisplayName("Invalid email - length")
  class LengthValidationTests {

    @Test
    @DisplayName("Should reject email exceeding 255 characters")
    void shouldRejectEmailExceedingMaxLength() {
      String longEmail = "a".repeat(250) + "@example.com"; // 262 characters

      Either<UserError, Email> result = Email.of(longEmail);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Email cannot exceed 255 characters");
    }

    @Test
    @DisplayName("Should accept email with exactly 255 characters")
    void shouldAcceptEmailWithMaxLength() {
      // Create an email with exactly 255 characters
      String localPart = "a".repeat(243);
      String email = localPart + "@example.com";

      Either<UserError, Email> result = Email.of(email);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).hasSize(255);
    }

    @Test
    @DisplayName("Should accept email with 254 characters")
    void shouldAcceptEmailJustUnderMaxLength() {
      String localPart = "a".repeat(241);
      String email = localPart + "@example.com"; // 254 characters

      Either<UserError, Email> result = Email.of(email);

      assertThat(result.isRight()).isTrue();
    }
  }
}