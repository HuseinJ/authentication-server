package com.hjusic.auth.domain.auth.model;

import com.hjusic.auth.domain.user.model.User;
import io.vavr.control.Either;

public interface Auth {

  Either<AuthError, User> findLoggedInUser();

}
