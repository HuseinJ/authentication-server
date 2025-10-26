package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessStartedEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ResetPasswordProcess Tests")
class ResetPasswordProcessTest {

  @Mock
  private Users users;

  @InjectMocks
  private ResetPasswordProcess resetPasswordProcess;

  @Mock
  private User mockUser;

  @Test
  @DisplayName("Should successfully initiate reset process for valid user")
  void shouldSuccessfullyInitiateResetProcess() {
    // Given
    String validUsername = "johndoe";
    ResetPasswordProcessStartedEvent event = mock(ResetPasswordProcessStartedEvent.class);
    User updatedUser = mock(User.class);

    when(users.findByUsername(validUsername)).thenReturn(Either.right(mockUser));
    when(mockUser.startResetPasswordProcess()).thenReturn(event);
    when(users.trigger(event)).thenReturn(updatedUser);

    // When
    Either<UserError, User> result = resetPasswordProcess.initiateResetPasswordProcess(validUsername);

    // Then
    assertThat(result.isRight()).isTrue();
    assertThat(result.get()).isEqualTo(updatedUser);
    verify(mockUser).startResetPasswordProcess();
    verify(users).trigger(event);
  }

  @Test
  @DisplayName("Should return error when username is invalid")
  void shouldReturnErrorWhenUsernameIsInvalid() {
    // When
    Either<UserError, User> result = resetPasswordProcess.initiateResetPasswordProcess("");

    // Then
    assertThat(result.isLeft()).isTrue();
    verify(users, never()).findByUsername(any());
  }

  @Test
  @DisplayName("Should return error when user does not exist")
  void shouldReturnErrorWhenUserDoesNotExist() {
    // Given
    String username = "nonexistent";
    when(users.findByUsername(username)).thenReturn(Either.left(UserError.creationFailed("Not found")));

    // When
    Either<UserError, User> result = resetPasswordProcess.initiateResetPasswordProcess(username);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).contains("User does not exist");
    verify(users, never()).trigger(any());
  }

  @Test
  @DisplayName("Should handle null username")
  void shouldHandleNullUsername() {
    // When
    Either<UserError, User> result = resetPasswordProcess.initiateResetPasswordProcess(null);

    // Then
    assertThat(result.isLeft()).isTrue();
    verify(users, never()).findByUsername(any());
  }
}