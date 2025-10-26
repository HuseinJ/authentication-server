package com.hjusic.auth.domain.user.application;

import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import io.vavr.control.Either;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ResetPasswordProcess {

  private final Users users;
  private final PasswordEncoder passwordEncoder;

  public Either<UserError, User> initiateResetPasswordProcess(String username) {
    var potentialUsername = Username.of(username);
    if(potentialUsername.isLeft()) {
      return Either.left(potentialUsername.getLeft());
    }

    var potentialUser = users.findByUsername(username);

    if(potentialUser.isLeft()) {
      return Either.left(UserError.creationFailed("User does not exist"));
    }

    var user = users.trigger(
        potentialUser.get().startResetPasswordProcess()
    );

    return Either.right(user);
  }

  public Either<UserError, User> completeResetPasswordProcess(String username, String token, String password) {
    var potentialUsername = Username.of(username);
    if(potentialUsername.isLeft()) {
      return Either.left(potentialUsername.getLeft());
    }

    var potentialUser = users.findByUsername(username);

    if(potentialUser.isLeft()) {
      return Either.left(UserError.creationFailed("User does not exist"));
    }

    var potentialPassword = Password.encode(password, passwordEncoder);
    if(potentialPassword.isLeft()) {
      return Either.left(potentialPassword.getLeft());
    }

    var potentialevent = potentialUser.get().completeResetPasswordProcess(potentialPassword.get(), token, users);

    if(potentialevent.isLeft()) {
      return Either.left(potentialevent.getLeft());
    }
    return Either.right(users.trigger(potentialevent.get()));
  }

}
