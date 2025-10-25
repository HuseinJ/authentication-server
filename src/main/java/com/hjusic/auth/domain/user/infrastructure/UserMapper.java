package com.hjusic.auth.domain.user.infrastructure;

import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseEntity;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.GuestUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {

  public User toModelObject(UserDatabaseEntity entity) {
    Set<String> roleNames = entity.getRoles().stream()
        .map(role -> role.getName().name())
        .collect(Collectors.toSet());

    // Determine the primary role (highest privilege)
    RoleName primaryRole = determinePrimaryRole(entity);

    return switch (primaryRole) {
      case ROLE_ADMIN -> mapToAdminUser(entity, roleNames);
      case ROLE_GUEST -> mapToGuestUser(entity, roleNames);
    };
  }

  private RoleName determinePrimaryRole(UserDatabaseEntity entity) {
    Set<RoleName> roles = entity.getRoles().stream()
        .map(RoleDatabaseEntity::getName)
        .collect(Collectors.toSet());

    // Priority order: ADMIN > GUEST
    if (roles.contains(RoleName.ROLE_ADMIN)) return RoleName.ROLE_ADMIN;
    return RoleName.ROLE_GUEST;
  }

  private AdminUser mapToAdminUser(UserDatabaseEntity entity, Set<String> roles) {

    var username = Username.of(entity.getUsername());

    if(username.isLeft()) {
      throw new IllegalStateException(username.getLeft().getMessage());
    }

    var email = Email.of(entity.getEmail());

    if(email.isLeft()) {
      throw new IllegalStateException(email.getLeft().getMessage());
    }

    return AdminUser.builder()
        .username(username.get())
        .email(email.get())
        .roles(roles)
        .build();
  }

  private GuestUser mapToGuestUser(UserDatabaseEntity entity, Set<String> roles) {
    var username = Username.of(entity.getUsername());

    if(username.isLeft()) {
      throw new IllegalStateException(username.getLeft().getMessage());
    }

    var email = Email.of(entity.getEmail());

    if(email.isLeft()) {
      throw new IllegalStateException(email.getLeft().getMessage());
    }

    return GuestUser.builder()
        .username(username.get())
        .email(email.get())
        .roles(roles)
        .build();
  }
}
