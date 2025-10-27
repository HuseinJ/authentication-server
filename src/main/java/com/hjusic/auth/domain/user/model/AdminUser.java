package com.hjusic.auth.domain.user.model;

import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import com.hjusic.auth.domain.user.model.event.UpdateRolesEvent;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import com.hjusic.auth.domain.user.model.event.UserDeletedEvent;
import io.vavr.control.Either;
import java.util.Set;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.experimental.SuperBuilder;

@Data
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
public class AdminUser extends User{
  private final String USER_TYPE = "ADMIN";

  @Override
  public String getUserType() {
    return USER_TYPE;
  }

  public UserCreatedEvent createUser(Username username, Email email, Password password, Set<RoleName> roles){
    return UserCreatedEvent.of(username, email, password, roles);
  }

  public Either<UserError, UserDeletedEvent> deleteUser(Username username, Users users){
    if (this.getUsername().equals(username)) {
      return Either.left(UserError.deletionFailed("Admin users cannot delete themselves"));
    }

    var potentialUser = users.findByUsername(username.getValue());

    if(potentialUser.isLeft()) {
      return Either.left(UserError.deletionFailed("User does not exist"));
    }

    return Either.right(UserDeletedEvent.of(username));
  }

  public Either<UserError, UpdateRolesEvent> updateRoles(User user, Set<Role> roles, Users users){
    var potentialUser = users.findByUsername(user.getUsername().getValue());

    if(potentialUser.isLeft()) {
      return Either.left(potentialUser.getLeft());
    }

    return Either.right(UpdateRolesEvent.of(user.getUsername(), roles));
  }
}
