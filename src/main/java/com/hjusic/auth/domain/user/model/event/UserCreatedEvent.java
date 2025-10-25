package com.hjusic.auth.domain.user.model.event;

import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;
import java.util.Set;
import lombok.Getter;

@Getter
public class UserCreatedEvent extends UserEvent {

  private final Password password;
  private final Set<RoleName> roles;

  private UserCreatedEvent(String eventId, Instant occurredOn, Username username, Password password,
      Email email, Set<RoleName> roles) {
    super(eventId, occurredOn, username, email);
    this.password = password;
    this.roles = roles;
  }

  public static UserCreatedEvent of(Username username, Email email, Password password,
      Set<RoleName> roles) {
    return new UserCreatedEvent(
        java.util.UUID.randomUUID().toString(),
        Instant.now(),
        username,
        password,
        email,
        roles
    );
  }
}
