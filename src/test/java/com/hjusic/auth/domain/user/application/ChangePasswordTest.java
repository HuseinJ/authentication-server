package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.event.ChangePasswordEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
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

  @Test
  @DisplayName("Should successfully change password when all validations pass")
  void shouldChangePasswordSuccessfully() {
    var event = mock(ChangePasswordEvent.class);
    User updatedUser = mock(User.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.matchesCurrentPassword(eq(OLD_PASSWORD))).thenReturn(Either.right(true));
    when(user.changePassword(any(Password.class))).thenReturn(event);
    when(users.trigger(event)).thenReturn(updatedUser);

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    assertThat(result.isRight()).isTrue();
    assertThat(result.get()).isEqualTo(updatedUser);
    verify(auth).findLoggedInUser();
    verify(auth).matchesCurrentPassword(eq(OLD_PASSWORD));
    verify(user).changePassword(any(Password.class));
    verify(users).trigger(event);
  }

  @Test
  @DisplayName("Should fail when old password is null")
  void shouldFailWhenOldPasswordIsNull() {
    Either<UserError, User> result = changePassword.changePassword(null, NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when old password is empty")
  void shouldFailWhenOldPasswordIsEmpty() {
    Either<UserError, User> result = changePassword.changePassword("", NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when old password is blank")
  void shouldFailWhenOldPasswordIsBlank() {
    Either<UserError, User> result = changePassword.changePassword("   ", NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password cannot be empty");
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when new password is invalid")
  void shouldFailWhenNewPasswordIsInvalid() {
    String weakPassword = "weak";

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, weakPassword);

    assertThat(result.isLeft()).isTrue();
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should fail when logged in user is not found")
  void shouldFailWhenUserNotFound() {
    when(auth.findLoggedInUser()).thenReturn(Either.left(AuthError.notAuthenticated()));

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("User does not exist");
    verify(auth).findLoggedInUser();
    verify(auth, never()).matchesCurrentPassword(any());
    verifyNoInteractions(users, user);
  }

  @Test
  @DisplayName("Should fail when password match check returns error")
  void shouldFailWhenMatchCheckErrors() {
    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.matchesCurrentPassword(eq(OLD_PASSWORD)))
        .thenReturn(Either.left(AuthError.notAuthenticated()));

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("User does not exist");
    verify(auth).findLoggedInUser();
    verify(auth).matchesCurrentPassword(eq(OLD_PASSWORD));
    verify(user, never()).changePassword(any(Password.class));
    verifyNoInteractions(users);
  }

  @Test
  @DisplayName("Should fail when old password does not match")
  void shouldFailWhenOldPasswordDoesNotMatch() {
    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.matchesCurrentPassword(eq(OLD_PASSWORD))).thenReturn(Either.right(false));

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).isEqualTo("Old password does not match");
    verify(auth).findLoggedInUser();
    verify(auth).matchesCurrentPassword(eq(OLD_PASSWORD));
    verify(user, never()).changePassword(any(Password.class));
    verifyNoInteractions(users);
  }

  @Test
  @DisplayName("Should propagate password validation error")
  void shouldPropagatePasswordValidationError() {
    String tooShortPassword = "123";

    Either<UserError, User> result = changePassword.changePassword(OLD_PASSWORD, tooShortPassword);

    assertThat(result.isLeft()).isTrue();
    verifyNoInteractions(auth, users, user);
  }

  @Test
  @DisplayName("Should handle all steps in correct order")
  void shouldHandleStepsInCorrectOrder() {
    var event = mock(ChangePasswordEvent.class);
    User updatedUser = mock(User.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(user));
    when(auth.matchesCurrentPassword(eq(OLD_PASSWORD))).thenReturn(Either.right(true));
    when(user.changePassword(any(Password.class))).thenReturn(event);
    when(users.trigger(event)).thenReturn(updatedUser);

    changePassword.changePassword(OLD_PASSWORD, NEW_PASSWORD);

    var inOrder = inOrder(auth, user, users);
    inOrder.verify(auth).findLoggedInUser();
    inOrder.verify(auth).matchesCurrentPassword(eq(OLD_PASSWORD));
    inOrder.verify(user).changePassword(any(Password.class));
    inOrder.verify(users).trigger(event);
  }
}
