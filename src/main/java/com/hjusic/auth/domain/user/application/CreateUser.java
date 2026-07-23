package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.role.model.RoleName;
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
import com.hjusic.auth.crypto.model.PasswordHasher;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CreateUser {

  private final Auth auth;
  private final PasswordHasher passwordHasher;
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

    var potentialPassword = Password.encode(password, passwordHasher);
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
      var validatedRoles = new java.util.HashSet<RoleName>();
      for (String role : roles) {
        try {
          validatedRoles.add(RoleName.valueOf(role));
        } catch (IllegalArgumentException ex) {
          return Either.left(UserError.creationFailed("Unknown role: " + role));
        }
      }

      var user = users.trigger(admin.createUser(
          potentialUsername.get(),
          potentialEmail.get(),
          potentialPassword.get(),
          validatedRoles
      ));

      return Either.right(user);
    }

    return Either.left(UserError.creationFailed(
        "Only admin users can create new users"
    ));
  }

}
