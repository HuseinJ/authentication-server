package com.hjusic.auth.domain.user.infrastructure;

import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessStartedEvent;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import com.hjusic.auth.domain.user.model.event.UserDeletedEvent;
import com.hjusic.auth.domain.user.model.event.UserEvent;
import com.hjusic.auth.event.model.DomainEventPublisher;
import io.vavr.control.Either;
import java.time.LocalDateTime;
import java.util.Collection;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class UserAppRepository implements Users {

  private final UserDatabaseRepository userRepository;
  private final ResetPasswordProcessDatabaseRepository resetPasswordProcessDatabaseRepository;
  private final UserMapper userMapper;
  private final DomainEventPublisher domainEventPublisher;

  @Override
  public Collection<User> findAll() {
    return userRepository.findAll().stream()
        .map(userMapper::toModelObject)
        .toList();
  }

  @Override
  public Either<UserError, User> findByUsername(String username) {
    return userRepository.findByUsername(username)
        .map(userDatabaseEntity -> Either.<UserError, User>right(
            userMapper.toModelObject(userDatabaseEntity)))
        .orElse(Either.left(UserError.userNotFound(username)));
  }

  @Override
  public Either<UserError, User> validateResetPasswordToken(String username, String token) {

    var userEntity = userRepository.findByUsername(username).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + username)
    );

    var resetPasswordTokens = resetPasswordProcessDatabaseRepository.findByUser(userEntity);

    if (resetPasswordTokens.stream().anyMatch(
        resetPasswordToken -> resetPasswordToken.getTokenHash().equals(token)
            && resetPasswordToken.getExpiresAt().isAfter(LocalDateTime.now()))) {
      return Either.right(userMapper.toModelObject(userEntity));
    }

    return Either.left(UserError.invalidResetPasswordToken("Invalid or expired reset password token for user: " + username));
  }

  @Override
  public User trigger(UserEvent event) {
    var user = switch (event) {
      case UserCreatedEvent e -> handle(e);
      case UserDeletedEvent e -> handle(e);
      case ResetPasswordProcessStartedEvent e -> handle(e);
      default -> throw new IllegalArgumentException("Unhandled event type: " + event.getClass());
    };

    domainEventPublisher.publish(event);

    return user;
  }

  private User handle(ResetPasswordProcessStartedEvent e) {
    var user = userRepository.findByUsername(e.getUsername().getValue()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername())
    );

    var resetPasswordProcesStarted = ResetPasswordProcessDatabaseEntity.builder()
        .createdAt(e.getResetPasswordToken().getCreatedOn())
        .expiresAt(e.getResetPasswordToken().getExpiresOn())
        .tokenHash(e.getResetPasswordToken().getTokenHash())
        .user(user)
        .build();

    resetPasswordProcessDatabaseRepository.save(resetPasswordProcesStarted);

    return userMapper.toModelObject(user);

  }

  private User handle(UserDeletedEvent e) {

    var user = userRepository.findByUsername(e.getUsername().getValue()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername())
    );
    userRepository.delete(user);

    return userMapper.toModelObject(user);
  }

  private User handle(UserCreatedEvent event) {
    var userDatabaseEntity = UserDatabaseEntity.builder()
        .email(event.getEmail().getValue())
        .username(event.getUsername().getValue())
        .password(event.getPassword().getValue())
        .build();

    return userMapper.toModelObject(userRepository.save(userDatabaseEntity));
  }
}
