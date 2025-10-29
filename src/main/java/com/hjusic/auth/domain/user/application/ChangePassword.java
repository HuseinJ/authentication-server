package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ChangePassword {

  private final Auth auth;
  private final Users users;
  private final PasswordEncoder passwordEncoder;

  public Either<UserError, User> changePassword(String oldPassword, String newPassword) {

    if(StringUtils.isBlank(oldPassword)){
      return Either.left(UserError.validationFailed("Old password cannot be empty"));
    }

    var potentialPassword = Password.encode(newPassword, passwordEncoder);

    if(potentialPassword.isLeft()) {
      return Either.left(potentialPassword.getLeft());
    }

    var user = auth.findLoggedInUser();

    if(user.isLeft()) {
      return Either.left(UserError.creationFailed("User does not exist"));
    }

    var passwordHash = auth.findPasswordHash();

    if(passwordHash.isLeft()) {
      return Either.left(UserError.creationFailed("User does not exist"));
    }

    var event = user.get().changePassword(potentialPassword.get(), oldPassword, passwordHash.get(), passwordEncoder);
    if(event.isLeft()) {
      return Either.left(event.getLeft());
    }

    return Either.right(users.trigger(event.get()));
  }

}
