package com.hjusic.auth.domain.user.model.ValueObjects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.hjusic.auth.domain.user.model.UserError;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import com.hjusic.auth.crypto.model.PasswordHasher;

import java.io.*;

class PasswordTest {

  private PasswordHasher passwordHasher;

  @BeforeEach
  void setUp() {
    passwordHasher = mock(PasswordHasher.class);
    when(passwordHasher.hash(anyString()))
        .thenAnswer(invocation -> "encoded_" + invocation.getArgument(0));
  }

  @Nested
  @DisplayName("Validation - empty or null")
  class EmptyValidationTests {

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"  ", "\t", "\n"})
    @DisplayName("Should reject null, empty or blank password")
    void shouldRejectNullOrBlankPassword(String password) {
      Either<UserError, Password> result = Password.encode(password, passwordHasher);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Password cannot be empty");
      verify(passwordHasher, never()).encode(anyString());
    }
  }

  @Nested
  @DisplayName("Validation - length")
  class LengthValidationTests {

    @ParameterizedTest
    @ValueSource(strings = {"a", "ab", "abc", "abcd", "abcde", "abcdef", "abcdefg"})
    @DisplayName("Should reject passwords shorter than 8 characters")
    void shouldRejectShortPasswords(String password) {
      Either<UserError, Password> result = Password.encode(password, passwordHasher);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Password must be at least 8 characters");
      verify(passwordHasher, never()).encode(anyString());
    }

    @Test
    @DisplayName("Should accept password with exactly 8 characters")
    void shouldAcceptMinimumLength() {
      Either<UserError, Password> result = Password.encode("12345678", passwordHasher);

      assertThat(result.isRight()).isTrue();
      verify(passwordHasher).encode("12345678");
    }

    @Test
    @DisplayName("Should accept password with exactly 128 characters")
    void shouldAcceptMaximumLength() {
      String password = "a".repeat(128);

      Either<UserError, Password> result = Password.encode(password, passwordHasher);

      assertThat(result.isRight()).isTrue();
      verify(passwordHasher).encode(password);
    }

    @Test
    @DisplayName("Should reject password with 129 characters")
    void shouldRejectPasswordTooLong() {
      String password = "a".repeat(129);

      Either<UserError, Password> result = Password.encode(password, passwordHasher);

      assertThat(result.isLeft()).isTrue();
      assertThat(result.getLeft().getMessage()).contains("Password cannot exceed 128 characters");
      verify(passwordHasher, never()).encode(anyString());
    }
  }

  @Nested
  @DisplayName("Encoding")
  class EncodingTests {

    @Test
    @DisplayName("Should encode valid password")
    void shouldEncodeValidPassword() {
      Either<UserError, Password> result = Password.encode("mypassword", passwordHasher);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isEqualTo("encoded_mypassword");
      verify(passwordHasher).encode("mypassword");
    }

    @Test
    @DisplayName("Should store encoded value, not plain text")
    void shouldStoreEncodedValue() {
      String plainPassword = "plainPassword123";

      Either<UserError, Password> result = Password.encode(plainPassword, passwordHasher);

      assertThat(result.isRight()).isTrue();
      assertThat(result.get().getValue()).isNotEqualTo(plainPassword);
      assertThat(result.get().getValue()).startsWith("encoded_");
    }

    @Test
    @DisplayName("Should not encode if validation fails")
    void shouldNotEncodeInvalidPassword() {
      Either<UserError, Password> result = Password.encode("short", passwordHasher);

      assertThat(result.isLeft()).isTrue();
      verify(passwordHasher, never()).encode(anyString());
    }

    @Test
    @DisplayName("Should preserve password exactly as provided before encoding")
    void shouldNotTrimPassword() {
      String passwordWithSpaces = " password ";

      Either<UserError, Password> result = Password.encode(passwordWithSpaces, passwordHasher);

      assertThat(result.isRight()).isTrue();
      verify(passwordHasher).encode(" password ");
    }
  }

  @Nested
  @DisplayName("Security - toString protection")
  class ToStringTests {

    @Test
    @DisplayName("Should not expose password in toString")
    void shouldNotExposePasswordInToString() {
      Password password = Password.encode("mypassword", passwordHasher).get();

      String toString = password.toString();

      assertThat(toString).isEqualTo("Password[PROTECTED]");
      assertThat(toString).doesNotContain("mypassword");
      assertThat(toString).doesNotContain("encoded_mypassword");
    }
  }
}