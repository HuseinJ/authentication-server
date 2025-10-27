package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import io.vavr.control.Either;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UpdateRoles {

  private final Users users;
  private final Auth auth;


  public Either<UserError, User> updateRoles(String username, Set<RoleName> roles) {
    var potentialUsername = Username.of(username);
    if(potentialUsername.isLeft()) {
      return Either.left(potentialUsername.getLeft());
    }

    var mappedRoles = roles.stream().map(Role::of).collect(Collectors.toSet());

    var loggedInUser = auth.findLoggedInUser();
    if(loggedInUser.isLeft()) {
      return Either.left(UserError.creationFailed(
          "Only authenticated users can update roles"
      ));
    }

    if(loggedInUser.get() instanceof AdminUser adminUser) {

      var potentialUser = users.findByUsername(username);
      if(potentialUser.isLeft()) {
        return Either.left(UserError.creationFailed("User does not exist"));
      }

      var event = adminUser.updateRoles(potentialUser.get(), mappedRoles, users);

      if(event.isLeft()) {
        return Either.left(event.getLeft());
      }

      return Either.right(users.trigger(event.get()));
    }

    return Either.left(UserError.creationFailed(
        "Only admin users can update roles"
    ));
  }

}
