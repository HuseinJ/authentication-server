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

class UsernameTest {

  @Nested
  @DisplayName("Valid username creation")
  class ValidUsernameTests {

    @Test
    @DisplayName("Should create username with valid format")
    void shouldCreateValidUsername() {
      Either<UserError, Username> result = Username.of("validuser");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("validuser");
    }

    @Test
    @DisplayName("Should trim whitespace from username")
    void shouldTrimWhitespace() {
      Either<UserError, Username> result = Username.of("  validuser  ");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("validuser");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "user",
        "user123",
        "user_name",
        "user-name",
        "User_Name-123",
        "abc",
        "a_b",
        "a-b",
        "user_123-test"
    })
    @DisplayName("Should accept valid username formats")
    void shouldAcceptValidFormats(String username) {
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept username with minimum length")
    void shouldAcceptMinimumLength() {
      Either<UserError, Username> result = Username.of("abc");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).hasSize(3);
    }

    @Test
    @DisplayName("Should accept username with maximum length")
    void shouldAcceptMaximumLength() {
      String username = "a".repeat(50);
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).hasSize(50);
    }

    @Test
    @DisplayName("Should accept username with only letters")
    void shouldAcceptOnlyLetters() {
      Either<UserError, Username> result = Username.of("username");

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept username with only numbers")
    void shouldAcceptOnlyNumbers() {
      Either<UserError, Username> result = Username.of("123456");

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept username with uppercase letters")
    void shouldAcceptUppercaseLetters() {
      Either<UserError, Username> result = Username.of("UserName");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("UserName");
    }

    @Test
    @DisplayName("Should accept username with underscores only")
    void shouldAcceptUnderscores() {
      Either<UserError, Username> result = Username.of("user_name_test");

      assertThat(result.isRight()).isTrue();
    }

    @Test
    @DisplayName("Should accept username with hyphens only")
    void shouldAcceptHyphens() {
      Either<UserError, Username> result = Username.of("user-name-test");

      assertThat(result.isRight()).isTrue();
    }
  }

  @Nested
  @DisplayName("Invalid username - null or empty")
  class NullOrEmptyTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n", "   "})
    @DisplayName("Should reject null, empty or blank username")
    void shouldRejectNullOrBlankUsername(String username) {
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username cannot be empty");
    }
  }

  @Nested
  @DisplayName("Invalid username - length")
  class LengthValidationTests {

    @Test
    @DisplayName("Should reject username with 2 characters")
    void shouldRejectUsernameTooShort() {
      Either<UserError, Username> result = Username.of("ab");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username must be at least 3 characters");
    }

    @Test
    @DisplayName("Should reject username with 1 character")
    void shouldRejectSingleCharacterUsername() {
      Either<UserError, Username> result = Username.of("a");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username must be at least 3 characters");
    }

    @Test
    @DisplayName("Should reject username exceeding 50 characters")
    void shouldRejectUsernameTooLong() {
      String username = "a".repeat(51);
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username cannot exceed 50 characters");
    }

    @Test
    @DisplayName("Should reject username with 100 characters")
    void shouldRejectVeryLongUsername() {
      String username = "a".repeat(100);
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username cannot exceed 50 characters");
    }

    @Test
    @DisplayName("Should reject username that becomes too short after trimming")
    void shouldRejectUsernameTooShortAfterTrimming() {
      Either<UserError, Username> result = Username.of("  ab  ");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Username must be at least 3 characters");
    }
  }

  @Nested
  @DisplayName("Invalid username - pattern")
  class PatternValidationTests {

    @ParameterizedTest
    @ValueSource(strings = {
        "user name",
        "user@name",
        "user.name",
        "user#name",
        "user$name",
        "user%name",
        "user&name",
        "user*name",
        "user(name",
        "user)name",
        "user+name",
        "user=name",
        "user[name",
        "user]name",
        "user{name",
        "user}name",
        "user|name",
        "user\\name",
        "user/name",
        "user:name",
        "user;name",
        "user\"name",
        "user'name",
        "user<name",
        "user>name",
        "user,name",
        "user?name"
    })
    @DisplayName("Should reject username with invalid characters")
    void shouldRejectInvalidCharacters(String username) {
      Either<UserError, Username> result = Username.of(username);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }

    @Test
    @DisplayName("Should reject username with spaces")
    void shouldRejectUsernameWithSpaces() {
      Either<UserError, Username> result = Username.of("user name");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }

    @Test
    @DisplayName("Should reject username with special characters")
    void shouldRejectUsernameWithSpecialCharacters() {
      Either<UserError, Username> result = Username.of("user@domain");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }

    @Test
    @DisplayName("Should reject username with dots")
    void shouldRejectUsernameWithDots() {
      Either<UserError, Username> result = Username.of("user.name");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }

    @Test
    @DisplayName("Should reject username with emoji")
    void shouldRejectUsernameWithEmoji() {
      Either<UserError, Username> result = Username.of("user😀name");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }

    @Test
    @DisplayName("Should reject username with accented characters")
    void shouldRejectUsernameWithAccentedCharacters() {
      Either<UserError, Username> result = Username.of("userñame");

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage())
          .contains("Username can only contain letters, numbers, underscores, and hyphens");
    }
  }

  @Nested
  @DisplayName("ToString method")
  class ToStringTests {

    @Test
    @DisplayName("ToString should return the username value")
    void toStringShouldReturnValue() {
      Either<UserError, Username> result = Username.of("testuser");

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().toString()).isEqualTo("testuser");
    }

    @Test
    @DisplayName("ToString should match getValue")
    void toStringShouldMatchGetValue() {
      Either<UserError, Username> result = Username.of("testuser");

      assertThat(result.isRight()).isTrue();
      Username username = result.get();
      assertThat(username.toString()).isEqualTo(username.getValue());
    }
  }
}