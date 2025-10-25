package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import com.hjusic.auth.domain.user.model.event.UserDeletedEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class DeleteUserTest {

  @Mock
  private Auth auth;

  @Mock
  private Users users;

  @InjectMocks
  private DeleteUser deleteUser;

  @Mock
  private AdminUser adminUser;

  @Mock
  private User regularUser;

  @Mock
  private User deletedUser;

  @Mock
  private Username mockUsername;

  @Test
  void shouldDeleteUserWhenAdminIsAuthenticatedAndUsernameIsValid() {
    // Given
    String username = "userToDelete";
    UserDeletedEvent deleteEvent = mock(UserDeletedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.right(deleteEvent));
    when(users.trigger(deleteEvent)).thenReturn(deletedUser);

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isRight());
    assertEquals(deletedUser, result.get());

    verify(auth).findLoggedInUser();
    verify(adminUser).deleteUser(any(Username.class), eq(users));
    verify(users).trigger(deleteEvent);
  }

  @Test
  void shouldPassCorrectUsernameToAdminDeleteUser() {
    // Given
    String username = "johndoe";
    UserDeletedEvent deleteEvent = mock(UserDeletedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.right(deleteEvent));
    when(users.trigger(any())).thenReturn(deletedUser);

    ArgumentCaptor<Username> usernameCaptor = ArgumentCaptor.forClass(Username.class);

    // When
    deleteUser.delete(username);

    // Then
    verify(adminUser).deleteUser(usernameCaptor.capture(), eq(users));
    assertNotNull(usernameCaptor.getValue());
  }

  @Test
  void shouldReturnErrorWhenUsernameIsNull() {
    // Given
    String username = null;

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("Username cannot be empty", result.getLeft().getMessage());

    verifyNoInteractions(auth, users);
  }

  @Test
  void shouldReturnErrorWhenUsernameIsEmpty() {
    // Given
    String username = "";

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("Username cannot be empty", result.getLeft().getMessage());

    verifyNoInteractions(auth, users);
  }

  @Test
  void shouldReturnErrorWhenUsernameIsBlank() {
    // Given
    String username = "   ";

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("Username cannot be empty", result.getLeft().getMessage());

    verifyNoInteractions(auth, users);
  }

  @Test
  void shouldReturnErrorWhenUsernameValidationFails() {
    // Given - assuming Username.of() validates format
    String invalidUsername = "invalid@user#name";

    // When
    var result = deleteUser.delete(invalidUsername);

    // Then
    assertTrue(result.isLeft());
    assertInstanceOf(UserError.class, result.getLeft());

    verifyNoInteractions(auth, users);
  }

  @Test
  void shouldReturnErrorWhenUserIsNotAuthenticated() {
    // Given
    String username = "userToDelete";
    AuthError authError = AuthError.notAuthenticated();

    when(auth.findLoggedInUser()).thenReturn(Either.left(authError));

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("Only authenticated users can delete users", result.getLeft().getMessage());

    verify(auth).findLoggedInUser();
    verifyNoInteractions(users);
  }

  @Test
  void shouldReturnErrorWhenAuthenticatedUserIsNotAdmin() {
    // Given
    String username = "userToDelete";

    when(auth.findLoggedInUser()).thenReturn(Either.right(regularUser));

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("Only admin user can delete users", result.getLeft().getMessage());

    verify(auth).findLoggedInUser();
    verifyNoInteractions(users);
  }

  @Test
  void shouldReturnErrorWhenAdminDeleteUserFails() {
    // Given
    String username = "userToDelete";
    UserError deleteError = UserError.deletionFailed("User not found");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.left(deleteError));

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isLeft());
    assertEquals("User not found", result.getLeft().getMessage());

    verify(auth).findLoggedInUser();
    verify(adminUser).deleteUser(any(Username.class), eq(users));
    verifyNoInteractions(users);
  }

  @Test
  void shouldValidateInputBeforeCheckingAuthentication() {
    // Given - blank username
    String blankUsername = "  ";

    // When
    var result = deleteUser.delete(blankUsername);

    // Then
    assertTrue(result.isLeft());

    // Auth should never be called if validation fails early
    verifyNoInteractions(auth);
  }

  @Test
  void shouldTriggerUsersRepositoryWithDeleteEvent() {
    // Given
    String username = "userToDelete";
    UserDeletedEvent deleteEvent = mock(UserDeletedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.right(deleteEvent));
    when(users.trigger(deleteEvent)).thenReturn(deletedUser);

    // When
    deleteUser.delete(username);

    // Then
    verify(adminUser).deleteUser(any(Username.class), eq(users));
    verify(users).trigger(deleteEvent);
  }

  @Test
  void shouldPassUsersRepositoryToAdminDeleteUser() {
    // Given
    String username = "userToDelete";
    UserDeletedEvent deleteEvent = mock(UserDeletedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), any(Users.class))).thenReturn(Either.right(deleteEvent));
    when(users.trigger(any())).thenReturn(deletedUser);

    ArgumentCaptor<Users> usersCaptor = ArgumentCaptor.forClass(Users.class);

    // When
    deleteUser.delete(username);

    // Then
    verify(adminUser).deleteUser(any(Username.class), usersCaptor.capture());
    assertEquals(users, usersCaptor.getValue());
  }

  @Test
  void shouldReturnDeletedUserFromRepository() {
    // Given
    String username = "userToDelete";
    UserDeletedEvent deleteEvent = mock(UserDeletedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.right(deleteEvent));
    when(users.trigger(deleteEvent)).thenReturn(deletedUser);

    // When
    var result = deleteUser.delete(username);

    // Then
    assertTrue(result.isRight());
    assertSame(deletedUser, result.get());
  }

  @Test
  void shouldNotTriggerRepositoryWhenDeleteEventCreationFails() {
    // Given
    String username = "userToDelete";
    UserError deleteError = UserError.deletionFailed("Cannot delete admin");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(adminUser.deleteUser(any(Username.class), eq(users))).thenReturn(Either.left(deleteError));

    // When
    deleteUser.delete(username);

    // Then
    verify(adminUser).deleteUser(any(Username.class), eq(users));
    verify(users, never()).trigger(any());
  }
}