package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.event.UpdateRolesEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class UpdateRolesTest {

  @Mock
  private Users users;

  @Mock
  private Auth auth;

  @Mock
  private AdminUser adminUser;

  @Mock
  private User targetUser;

  @Mock
  private User updatedUser;

  private UpdateRoles updateRoles;

  @BeforeEach
  void setUp() {
    updateRoles = new UpdateRoles(users, auth);
  }

  @Test
  void shouldSuccessfullyUpdateRolesWhenAdminUserAndValidUsername() {
    // Given
    String username = "testuser";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST, RoleName.ROLE_ADMIN);
    Set<Role> mappedRoles = Set.of(Role.of(RoleName.ROLE_GUEST), Role.of(RoleName.ROLE_ADMIN));

    var updateEvent = Either.right(mock(UpdateRolesEvent.class));

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(users.findByUsername(username)).thenReturn(Either.right(targetUser));
    when(adminUser.updateRoles(eq(targetUser), any(Set.class), eq(users)))
        .thenReturn(updateEvent);
    when(users.trigger(any())).thenReturn(updatedUser);

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, roleNames);

    // Then
    assertThat(result.isRight()).isTrue();
    assertThat(result.get()).isEqualTo(updatedUser);

    verify(auth).findLoggedInUser();
    verify(users).findByUsername(username);
    verify(adminUser).updateRoles(eq(targetUser), any(Set.class), eq(users));
    verify(users).trigger(any());
  }

  @Test
  void shouldReturnErrorWhenUsernameIsInvalid() {
    // Given
    String invalidUsername = "";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST);

    // When
    Either<UserError, User> result = updateRoles.updateRoles(invalidUsername, roleNames);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft()).isInstanceOf(UserError.class);

    verify(auth, never()).findLoggedInUser();
    verify(users, never()).findByUsername(any());
  }

  @Test
  void shouldReturnErrorWhenNoUserIsLoggedIn() {
    // Given
    String username = "testuser";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST);
    AuthError authError = AuthError.notAuthenticated();

    when(auth.findLoggedInUser()).thenReturn(Either.left(authError));

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, roleNames);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage())
        .contains("Only authenticated users can update roles");

    verify(auth).findLoggedInUser();
    verify(users, never()).findByUsername(any());
  }

  @Test
  void shouldReturnErrorWhenLoggedInUserIsNotAdmin() {
    // Given
    String username = "testuser";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST);
    User regularUser = mock(User.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(regularUser));

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, roleNames);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage())
        .contains("Only admin users can update roles");

    verify(auth).findLoggedInUser();
    verify(users, never()).findByUsername(any());
  }

  @Test
  void shouldReturnErrorWhenTargetUserDoesNotExist() {
    // Given
    String username = "nonexistentuser";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST);
    UserError userNotFoundError = UserError.creationFailed("User not found");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(users.findByUsername(username)).thenReturn(Either.left(userNotFoundError));

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, roleNames);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft().getMessage()).contains("User does not exist");

    verify(auth).findLoggedInUser();
    verify(users).findByUsername(username);
    verify(adminUser, never()).updateRoles(any(), any(), any());
  }

  @Test
  void shouldReturnErrorWhenUpdateRolesFails() {
    // Given
    String username = "testuser";
    Set<RoleName> roleNames = Set.of(RoleName.ROLE_GUEST);
    UserError updateError = UserError.creationFailed("Role update failed");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(users.findByUsername(username)).thenReturn(Either.right(targetUser));
    when(adminUser.updateRoles(eq(targetUser), any(Set.class), eq(users)))
        .thenReturn(Either.left(updateError));

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, roleNames);

    // Then
    assertThat(result.isLeft()).isTrue();
    assertThat(result.getLeft()).isEqualTo(updateError);

    verify(auth).findLoggedInUser();
    verify(users).findByUsername(username);
    verify(adminUser).updateRoles(eq(targetUser), any(Set.class), eq(users));
    verify(users, never()).trigger(any());
  }

  @Test
  void shouldHandleEmptyRolesSet() {
    // Given
    String username = "testuser";
    Set<RoleName> emptyRoles = Set.of();
    var updateEvent = Either.right(mock(UpdateRolesEvent.class));

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(users.findByUsername(username)).thenReturn(Either.right(targetUser));
    when(adminUser.updateRoles(eq(targetUser), any(Set.class), eq(users)))
        .thenReturn(updateEvent);
    when(users.trigger(any())).thenReturn(updatedUser);

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, emptyRoles);

    // Then
    assertThat(result.isRight()).isTrue();
    assertThat(result.get()).isEqualTo(updatedUser);

    verify(adminUser).updateRoles(eq(targetUser), any(Set.class), eq(users));
  }

  @Test
  void shouldHandleMultipleRoles() {
    // Given
    String username = "testuser";
    Set<RoleName> multipleRoles = Set.of(
        RoleName.ROLE_GUEST,
        RoleName.ROLE_ADMIN
    );
    var updateEvent = Either.right(mock(UpdateRolesEvent.class));

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(users.findByUsername(username)).thenReturn(Either.right(targetUser));
    when(adminUser.updateRoles(eq(targetUser), any(Set.class), eq(users)))
        .thenReturn(updateEvent);
    when(users.trigger(any())).thenReturn(updatedUser);

    // When
    Either<UserError, User> result = updateRoles.updateRoles(username, multipleRoles);

    // Then
    assertThat(result.isRight()).isTrue();
    verify(adminUser).updateRoles(eq(targetUser), argThat(roles ->
        roles.size() == 2
    ), eq(users));
  }
}