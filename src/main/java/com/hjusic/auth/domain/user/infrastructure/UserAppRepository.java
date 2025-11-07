package com.hjusic.auth.domain.user.infrastructure;

import com.hjusic.auth.domain.role.infrastructure.RoleDatabaseRepository;
import com.hjusic.auth.domain.role.model.Role;
import com.hjusic.auth.domain.user.model.User;
import com.hjusic.auth.domain.user.model.UserError;
import com.hjusic.auth.domain.user.model.Users;
import com.hjusic.auth.domain.user.model.ValueObjects.ResetPasswordToken;
import com.hjusic.auth.domain.user.model.event.ChangePasswordEvent;
import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessComplete;
import com.hjusic.auth.domain.user.model.event.ResetPasswordProcessStartedEvent;
import com.hjusic.auth.domain.user.model.event.UpdateRolesEvent;
import com.hjusic.auth.domain.user.model.event.UserCreatedEvent;
import com.hjusic.auth.domain.user.model.event.UserDeletedEvent;
import com.hjusic.auth.domain.user.model.event.UserEvent;
import com.hjusic.auth.event.model.DomainEventPublisher;
import io.vavr.control.Either;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@AllArgsConstructor
public class UserAppRepository implements Users {

  private final UserDatabaseRepository userRepository;
  private final RoleDatabaseRepository roleDatabaseEntityRepository;
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

    // Find valid token
    var validToken = resetPasswordTokens.stream()
        .filter(resetPasswordToken ->
            ResetPasswordToken.verifyToken(token, resetPasswordToken.getTokenHash())
                && !resetPasswordToken.isUsed()
                && resetPasswordToken.getExpiresAt().isAfter(LocalDateTime.now())
        )
        .findFirst();

    if (validToken.isPresent()) {
      var resetProcess = validToken.get();

      // Mark as used
      resetProcess.setUsed(true);
      resetProcess.setUsedAt(LocalDateTime.now());
      resetPasswordProcessDatabaseRepository.save(resetProcess);

      return Either.right(userMapper.toModelObject(userEntity));
    }

    return Either.left(UserError.invalidResetPasswordToken(
        "Invalid or expired reset password token for user: " + username));
  }

  @Override
  public User trigger(UserEvent event) {
    var user = switch (event) {
      case UserCreatedEvent e -> handle(e);
      case UserDeletedEvent e -> handle(e);
      case ResetPasswordProcessStartedEvent e -> handle(e);
      case ResetPasswordProcessComplete e -> handle(e);
      case UpdateRolesEvent e -> handle(e);
      case ChangePasswordEvent e -> handle(e);
      default -> throw new IllegalArgumentException("Unhandled event type: " + event.getClass());
    };

    domainEventPublisher.publish(event);

    return user;
  }

  private User handle(ChangePasswordEvent e) {
    var user = userRepository.findByUsername(e.getUsername().getValue()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername())
    );

    user.setPassword(e.getPassword().getValue());

    return userMapper.toModelObject(userRepository.save(user));
  }

  private User handle(UpdateRolesEvent e) {
    var user = userRepository.findByUsername(e.getUsername().getValue()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername())
    );

    var roles = roleDatabaseEntityRepository.findAllByNameIn(e.getRoles().stream().map(Role::getName).collect(
        Collectors.toSet()));
    user.setRoles(roles);

    return userMapper.toModelObject(userRepository.save(user));
  }

  private User handle(ResetPasswordProcessComplete e) {
    var user = userRepository.findByUsername(e.getUsername().getValue()).orElseThrow(
        () -> new IllegalArgumentException("User does not exist: " + e.getUsername())
    );
    user.setPassword(e.getPassword().getValue());
    return userMapper.toModelObject(userRepository.save(user));
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
        .used(false)
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
    var roles = roleDatabaseEntityRepository.findAllByNameIn(event.getRoles());

    var userDatabaseEntity = UserDatabaseEntity.builder()
        .email(event.getEmail().getValue())
        .username(event.getUsername().getValue())
        .password(event.getPassword().getValue())
        .roles(roles)
        .build();

    return userMapper.toModelObject(userRepository.save(userDatabaseEntity));
  }
}
