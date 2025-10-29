package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.event.ChangePasswordEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ChangePassword Service Tests")
class ChangePasswordTest {

  @Mock
  private Auth auth;

  @Mock
  private Users users;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private User user;

  @InjectMocks
  private ChangePassword changePassword;

  private static final String OLD_PASSWORD = "oldPassword123!";
  private static final String NEW_PASSWORD = "newPassword456!";
  private static final String PASSWORD_HASH = "$2a$10$hashedPassword";

  @Test
  @DisplayName("Should successfully change password when all validations pass")
  void shouldChangePasswordSuccessfully() {
    // Given
    var event = mock(ChangePasswordEvent.class);
    User updatedUser = mock(User.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.findPasswordHash()).thenReturn(Either.right(PASSWORD_HASH));
    when(user.changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder)))
        .thenReturn(Either.right(event));
    when(users.trigger(event)).thenReturn(updatedUser);

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then
    assertThat(result.isRight()).isTrue();
    assertThat(result.get()).isEqualTo(updatedUser);
    verify(auth).findLoggedInUser();
    verify(auth).findPasswordHash();
    verify(user).changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder));
    verify(users).trigger(event);
  }

  @Test
  @DisplayName("Should fail when old password is null")
  void shouldFailWhenOldPasswordIsNull() {
    // When
    Either<UserError, User> result = changePassword.changePassword(null, NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when old password is empty")
  void shouldFailWhenOldPasswordIsEmpty() {
    // When
    Either<UserError, User> result = changePassword.changePassword("", NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when old password is blank")
  void shouldFailWhenOldPasswordIsBlank() {
    // When
    Either<UserError, User> result = changePassword.changePassword("   ", NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when new password is invalid")
  void shouldFailWhenNewPasswordIsInvalid() {
    // Given
    String weakPassword = "weak";

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, weakPassword);

    // Then
    assertThat(result.isLeft()).isTrue();
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when logged in user is not found")
  void shouldFailWhenUserNotFound() {
    // Given
    when(auth.findLoggedInUser()).thenReturn(Either.left(AuthError.notAuthenticated()));

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("User does not exist");
    verify(auth).findLoggedInUser();
    verify(auth, never()).findPasswordHash();
    verifyNoInteractions(users, user);
  }

  @Test
  @DisplayName("Should fail when password hash is not found")
  void shouldFailWhenPasswordHashNotFound() {
    // Given
    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.findPasswordHash()).thenReturn(Either.left(AuthError.notAuthenticated()));

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("User does not exist");
    verify(auth).findLoggedInUser();
    verify(auth).findPasswordHash();
    verify(user, never()).changePassword(any(), anyString(), anyString(), any());
    verifyNoInteractions(users);
  }

  @Test
  @DisplayName("Should fail when old password does not match")
  void shouldFailWhenOldPasswordDoesNotMatch() {
    // Given
    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.findPasswordHash()).thenReturn(Either.right(PASSWORD_HASH));
    when(user.changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder)))
        .thenReturn(Either.left(UserError.validationFailed("Old password is incorrect")));

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password is incorrect");
    verify(auth).findLoggedInUser();
    verify(auth).findPasswordHash();
    verify(user).changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder));
    verifyNoInteractions(users);
  }

  @Test
  @DisplayName("Should fail when user.changePassword returns error")
  void shouldFailWhenChangePasswordReturnsError() {
    // Given
    UserError error = UserError.validationFailed("Password change failed");
    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.findPasswordHash()).thenReturn(Either.right(PASSWORD_HASH));
    when(user.changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder)))
        .thenReturn(Either.left(error));

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft()).isEqualTo(error);
    verify(users, never()).trigger(any());
  }

  @Test
  @DisplayName("Should propagate password validation error")
  void shouldPropagatePasswordValidationError() {
    // Given - new password is too short (assuming Password.encode validates this)
    String tooShortPassword = "123";

    // When
    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, tooShortPassword);

    // Then
    assertThat(result.isLeft()).isTrue();
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should handle all steps in correct order")
  void shouldHandleStepsInCorrectOrder() {
    // Given
    Password newPasswordVO = mock(Password.class);
    var event = mock(ChangePasswordEvent.class);
    User updatedUser = mock(User.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.findPasswordHash()).thenReturn(Either.right(PASSWORD_HASH));
    when(user.changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder)))
        .thenReturn(Either.right(event));
    when(users.trigger(event)).thenReturn(updatedUser);

    // When
    changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    // Then - verify order of execution
    var inOrder = inOrder(auth, user, users);
    inOrder.verify(auth).findLoggedInUser();
    inOrder.verify(auth).findPasswordHash();
    inOrder.verify(user).changePassword(any(Password.class), eq(OLD_PASSWORD), eq(PASSWORD_HASH), eq(passwordEncoder));
    inOrder.verify(users).trigger(event);
  }
}