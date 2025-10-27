package com.hjusic.auth.domain.user.infrastructure;

import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseEntity;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.GuestUser;
import com.hjusic.auth.domain.user.model.User;
import java.util.Objects;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UserMapperTest {

  private UserMapper userMapper;

  @BeforeEach
  void setUp() {
    userMapper = new UserMapper();
  }

  @Test
  void shouldMapToAdminUser_whenEntityHasAdminRole() {
    // Given
    RoleDatabaseEntity adminRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_ADMIN)
        .build();

    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("adminuser")
        .email("admin@example.com")
        .roles(Set.of(adminRole))
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result).isInstanceOf(AdminUser.class);
    AdminUser adminUser = (AdminUser) result;
    assertThat(adminUser.getUsername().getValue()).isEqualTo("adminuser");
    assertThat(adminUser.getEmail().getValue()).isEqualTo("admin@example.com");
    assertThat(adminUser.getRoles()).containsExactly(Role.of(RoleName.ROLE_ADMIN));
  }

  @Test
  void shouldMapToGuestUser_whenEntityHasGuestRole() {
    // Given
    RoleDatabaseEntity guestRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_GUEST)
        .build();

    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("guestuser")
        .email("guest@example.com")
        .roles(Set.of(guestRole))
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result).isInstanceOf(GuestUser.class);
    GuestUser guestUser = (GuestUser) result;
    assertThat(guestUser.getUsername().getValue()).isEqualTo("guestuser");
    assertThat(guestUser.getEmail().getValue()).isEqualTo("guest@example.com");
    assertThat(guestUser.getRoles()).containsExactly(Role.of(RoleName.ROLE_GUEST));
  }

  @Test
  void shouldMapToGuestUser_whenEntityHasNoRoles() {
    // Given
    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("noroleuser")
        .email("norole@example.com")
        .roles(Set.of())
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result).isInstanceOf(GuestUser.class);
    GuestUser guestUser = (GuestUser) result;
    assertThat(guestUser.getUsername().getValue()).isEqualTo("noroleuser");
    assertThat(guestUser.getEmail().getValue()).isEqualTo("norole@example.com");
    assertThat(guestUser.getRoles()).isEmpty();
  }

  @Test
  void shouldPrioritizeAdminRole_whenEntityHasMultipleRoles() {
    // Given
    RoleDatabaseEntity adminRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_ADMIN)
        .build();

    RoleDatabaseEntity guestRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_GUEST)
        .build();

    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("multiuser")
        .email("multi@example.com")
        .roles(Set.of(adminRole, guestRole))
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result).isInstanceOf(AdminUser.class);
    AdminUser adminUser = (AdminUser) result;
    assertThat(adminUser.getRoles()).containsExactlyInAnyOrder(Role.of(RoleName.ROLE_ADMIN), Role.of(RoleName.ROLE_GUEST));
  }

  @Test
  void shouldMapAllRoles_whenEntityHasMultipleRoles() {
    // Given
    RoleDatabaseEntity adminRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_ADMIN)
        .build();

    RoleDatabaseEntity guestRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_GUEST)
        .build();

    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("allroles")
        .email("allroles@example.com")
        .roles(Set.of(adminRole, guestRole))
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result.getRoles())
        .hasSize(2)
        .containsExactlyInAnyOrder(Role.of(RoleName.ROLE_ADMIN), Role.of(RoleName.ROLE_GUEST));
  }

  @Test
  void shouldPreserveUsername() {
    // Given
    RoleDatabaseEntity adminRole = RoleDatabaseEntity.builder()
        .name(RoleName.ROLE_ADMIN)
        .build();

    UserDatabaseEntity entity = UserDatabaseEntity.builder()
        .username("specificUsername123")
        .email("test@example.com")
        .roles(Set.of(adminRole))
        .build();

    // When
    User result = userMapper.toModelObject(entity);

    // Then
    assertThat(result.getUsername().getValue()).isEqualTo("specificUsername123");
  }
}