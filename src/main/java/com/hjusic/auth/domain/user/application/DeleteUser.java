package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import io.micrometer.common.util.StringUtils;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DeleteUser {

  private final Auth auth;
  private final Users users;

  public Either<UserError, User> delete(String username) {

    if (StringUtils.isBlank(username)) {
      return Either.left(UserError.validationFailed("Username cannot be empty"));
    }

    var potentialUsername = Username.of(username);
    if(potentialUsername.isLeft()) {
      return Either.left(potentialUsername.getLeft());
    }

    var loggedInUser = auth.findLoggedInUser();
    if(loggedInUser.isLeft()) {
      return Either.left(UserError.creationFailed(
          "Only authenticated users can delete users"
      ));
    }

    if (loggedInUser.get() instanceof AdminUser admin) {
      var potentialEvent = admin.deleteUser(potentialUsername.get(), users);

      if(potentialEvent.isLeft()) {
        return Either.left(potentialEvent.getLeft());
      }

      return Either.right(users.trigger(
          potentialEvent.get()
      ));
    }

    return Either.left(UserError.creationFailed(
        "Only admin user can delete users"
    ));

  }

}
