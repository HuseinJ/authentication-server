package com.hjusic.auth.domain.user.model.event;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.hjusic.auth.domain.role.infrastructure.RoleName;
import com.hjusic.auth.domain.user.model.ValueObjects.Email;
import com.hjusic.auth.domain.user.model.ValueObjects.Password;
import com.hjusic.auth.domain.user.model.ValueObjects.Username;
import java.time.Instant;
import java.util.Set;
import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@EqualsAndHashCode(callSuper = true)
public class UserCreatedEvent extends UserEvent {

  @JsonIgnore
  private Password password;
  private Set<RoleName> roles;

  public static UserCreatedEvent of(Username username, Email email, Password password, Set<RoleName> roles) {
    UserCreatedEvent event = new UserCreatedEvent();
    event.setEventId(java.util.UUID.randomUUID().toString());
    event.setOccurredOn(Instant.now());
    event.setUsername(username);
    event.setEmail(email);
    event.setPassword(password);
    event.setRoles(roles);
    return event;
  }

  @Override
  public String getEventType() {
    return "UserCreatedEvent";
  }
}