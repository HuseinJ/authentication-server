package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.AdminUser;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import io.vavr.control.Either;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateUser {

  private final Auth auth;
  private final PasswordEncoder passwordEncoder;
  private final Users users;

  public Either<UserError, User> create(String username, String email, String password,
      Set<String> roles) {

    var potentialUsername = Username.of(username);
    if(potentialUsername.isLeft()) {
      return Either.left(potentialUsername.getLeft());
    }

    var potentialEmail = Email.of(email);
    if(potentialEmail.isLeft()) {
      return Either.left(potentialEmail.getLeft());
    }

    var potentialPassword = Password.encode(password, passwordEncoder);
    if(potentialPassword.isLeft()) {
      return Either.left(potentialPassword.getLeft());
    }

    var loggedInUser = auth.findLoggedInUser();

    if(loggedInUser.isLeft()) {
      return Either.left(UserError.creationFailed(
          "Only authenticated users can create new users"
      ));
    }

    if (loggedInUser.get() instanceof AdminUser admin) {
      var user = users.trigger(admin.createUser(
          potentialUsername.get(),
          potentialEmail.get(),
          potentialPassword.get(),
          roles.stream().map(RoleName::valueOf).collect(java.util.stream.Collectors.toSet())
      ));

      return Either.right(user);
    }

    return Either.left(UserError.creationFailed(
        "Only admin users can create new users"
    ));
  }

}
