package com.hjusic.auth.domain.user.model;

import com.hjusic.auth.domain.user.model.event.UserEvent;
import io.vavr.control.Either;
import java.util.Collection;

public interface Users {

  Collection<User> findAll();

  Either<UserError, User> findByUsername(String username);

  Either<UserError, User> validateResetPasswordToken(String username, String token);

  User trigger(UserEvent event);

}
