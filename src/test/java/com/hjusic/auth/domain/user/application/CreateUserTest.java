package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import io.vavr.control.Either;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CreateUserTest {

  @Mock
  private Auth auth;

  @Mock
  private PasswordEncoder passwordEncoder;

  @Mock
  private Users users;

  @InjectMocks
  private CreateUser createUser;

  @Mock
  private AdminUser adminUser;

  @Mock
  private User regularUser;

  @Mock
  private User createdUser;

  @Test
  void shouldCreateUserWhenAdminIsAuthenticatedAndInputIsValid() {
    // Given
    String username = "mando";
    String email = "john@example.com";
    String password = "SecurePass123!";
    Set<String> roles = Set.of("ROLE_GUEST");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(passwordEncoder.encode(password)).thenReturn("encoded_password");
    when(adminUser.createUser(any(), any(), any(), anySet())).thenReturn(mock(UserCreatedEvent.class));
    when(users.trigger(any())).thenReturn(createdUser);

    // When
    var result = createUser.create(username, email, password, roles);

    // Then
    assertTrue(result.isRight());
    assertEquals(createdUser, result.get());

    verify(auth).findLoggedInUser();
    verify(passwordEncoder).encode(password);
    verify(users).trigger(any());
  }

  @Test
  void shouldPassCorrectRolesToAdminCreateUser() {
    // Given
    Set<String> roles = Set.of("ROLE_ADMIN", "ROLE_GUEST");

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(passwordEncoder.encode(anyString())).thenReturn("encoded");
    when(adminUser.createUser(any(), any(), any(), anySet())).thenReturn(mock(UserCreatedEvent.class));
    when(users.trigger(any())).thenReturn(createdUser);

    ArgumentCaptor<Set<RoleName>> rolesCaptor = ArgumentCaptor.forClass(Set.class);

    // When
    createUser.create("user", "user@test.com", "Pass123!", roles);

    // Then
    verify(adminUser).createUser(any(), any(), any(), rolesCaptor.capture());
    Set<RoleName> capturedRoles = rolesCaptor.getValue();

    assertEquals(2, capturedRoles.size());
    assertTrue(capturedRoles.contains(RoleName.ROLE_ADMIN));
    assertTrue(capturedRoles.contains(RoleName.ROLE_GUEST));
  }

  @Test
  void shouldReturnErrorWhenUsernameValidationFails() {
    // Given - empty username should fail validation
    String invalidUsername = "";

    // When
    var result = createUser.create(invalidUsername, "valid@email.com", "ValidPass123!", Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());
    assertInstanceOf(UserError.class, result.getLeft());

    verifyNoInteractions(auth, passwordEncoder, users);
  }

  @Test
  void shouldReturnErrorWhenEmailValidationFails() {
    // Given - invalid email format
    String invalidEmail = "not-an-email";

    // When
    var result = createUser.create("validuser", invalidEmail, "ValidPass123!", Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());
    assertInstanceOf(UserError.class, result.getLeft());

    verifyNoInteractions(auth, passwordEncoder, users);
  }

  @Test
  void shouldReturnErrorWhenPasswordValidationFails() {
    // Given - password too weak
    String weakPassword = "123";

    // When
    var result = createUser.create("validuser", "valid@email.com", weakPassword, Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());
    assertInstanceOf(UserError.class, result.getLeft());

    verifyNoInteractions(auth, passwordEncoder, users);
  }

  @Test
  void shouldReturnErrorWhenUserIsNotAuthenticated() {
    // Given
    AuthError authError = AuthError.notAuthenticated();
    when(auth.findLoggedInUser()).thenReturn(Either.left(authError));
    when(passwordEncoder.encode(anyString())).thenReturn("encoded");

    // When
    var result = createUser.create("user", "user@test.com", "Pass123!", Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());
    assertEquals("Only authenticated users can create new users", result.getLeft().getMessage());

    verify(auth).findLoggedInUser();
    verifyNoInteractions(users);
  }

  @Test
  void shouldReturnErrorWhenAuthenticatedUserIsNotAdmin() {
    // Given - regular user (not admin) is authenticated
    when(auth.findLoggedInUser()).thenReturn(Either.right(regularUser));
    when(passwordEncoder.encode(anyString())).thenReturn("encoded");

    // When
    var result = createUser.create("newuser", "new@test.com", "Pass123!", Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());
    assertEquals("Only admin users can create new users", result.getLeft().getMessage());

    verify(auth).findLoggedInUser();
    verifyNoInteractions(users);
  }

  @Test
  void shouldValidateInputsBeforeCheckingAuthentication() {
    // Given - invalid username
    String invalidUsername = "";

    // When
    var result = createUser.create(invalidUsername, "test@test.com", "Pass123!", Set.of("ROLE_USER"));

    // Then
    assertTrue(result.isLeft());

    // Auth should never be called if validation fails
    verifyNoInteractions(auth);
  }

  @Test
  void shouldEncodePasswordBeforePassingToAdminUser() {
    // Given
    String rawPassword = "MySecurePassword123!";
    String encodedPassword = "encoded_hash_value";

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(passwordEncoder.encode(rawPassword)).thenReturn(encodedPassword);
    when(adminUser.createUser(any(), any(), any(), anySet())).thenReturn(mock(UserCreatedEvent.class));
    when(users.trigger(any())).thenReturn(createdUser);

    ArgumentCaptor<Password> passwordCaptor = ArgumentCaptor.forClass(Password.class);

    // When
    createUser.create("user", "user@test.com", rawPassword, Set.of("ROLE_GUEST"));

    // Then
    verify(passwordEncoder).encode(rawPassword);
    verify(adminUser).createUser(any(), any(), passwordCaptor.capture(), anySet());

    // Password object should be created with encoded value
    assertNotNull(passwordCaptor.getValue());
  }

  @Test
  void shouldTriggerUsersRepositoryWithCreatedUserEvent() {
    // Given
    UserCreatedEvent userCreatedEvent = mock(UserCreatedEvent.class);

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(passwordEncoder.encode(anyString())).thenReturn("encoded");
    when(adminUser.createUser(any(), any(), any(), anySet())).thenReturn(userCreatedEvent);
    when(users.trigger(userCreatedEvent)).thenReturn(createdUser);

    // When
    createUser.create("user", "user@test.com", "Pass123!", Set.of("ROLE_GUEST"));

    // Then
    verify(adminUser).createUser(any(), any(), any(), anySet());
    verify(users).trigger(userCreatedEvent);
  }

  @Test
  void shouldHandleEmptyRolesSet() {
    // Given
    Set<String> emptyRoles = Set.of();

    when(auth.findLoggedInUser()).thenReturn(Either.right(adminUser));
    when(passwordEncoder.encode(anyString())).thenReturn("encoded");
    when(adminUser.createUser(any(), any(), any(), anySet())).thenReturn(mock(UserCreatedEvent.class));
    when(users.trigger(any())).thenReturn(createdUser);

    ArgumentCaptor<Set<RoleName>> rolesCaptor = ArgumentCaptor.forClass(Set.class);

    // When
    var result = createUser.create("user", "user@test.com", "Pass123!", emptyRoles);

    // Then
    assertTrue(result.isRight());
    verify(adminUser).createUser(any(), any(), any(), rolesCaptor.capture());
    assertTrue(rolesCaptor.getValue().isEmpty());
  }
}