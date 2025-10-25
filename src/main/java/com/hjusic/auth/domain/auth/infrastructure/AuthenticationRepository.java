package com.hjusic.auth.domain.auth.infrastructure;

import com.hjusic.auth.domain.auth.model.Auth;
import com.hjusic.auth.domain.auth.model.AuthError;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.Users;
import io.vavr.control.Either;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
class AuthenticationRepository implements Auth {

  private final Users users;

  @Override
  public Either<AuthError, User> findLoggedInUser() {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

      if (authentication == null || !authentication.isAuthenticated()) {
        return Either.left(AuthError.notAuthenticated());
      }

      String username = authentication.getName();

      var potentialUser = users.findByUsername(username);
      if (potentialUser.isLeft()) {
        return Either.left(AuthError.notAuthenticated());
      }

      return Either.right(potentialUser.get());


    } catch (Exception e) {
      return Either.left(AuthError.notAuthenticated(e.getMessage()));
    }
  }
}
